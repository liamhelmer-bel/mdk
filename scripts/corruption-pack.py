#!/usr/bin/env python3
"""Build a PRIVATE, bounded evidence archive; never upload or repair anything."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import tarfile
import time

LIMIT = 4 * 1024 * 1024


def run_bounded(argv, limit=LIMIT, timeout=10):
    """Drain one combined pipe with a byte and wall-clock deadline."""
    data = bytearray()
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL)
    except OSError as error:
        return b"", {"available": False, "error_kind": type(error).__name__}
    reason = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                if not selector.select(remaining):
                    reason = "timeout"
                    break
                chunk = os.read(proc.stdout.fileno(), min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    reason = "byte_limit"
                    break
        if reason is None:
            try:
                proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                reason = "timeout"
    finally:
        if proc.poll() is None:
            proc.kill()
        code = proc.wait()
        proc.stdout.close()
    return bytes(data[:limit]), {"available": True, "exit_code": code,
                                "incomplete_reason": reason}


def read_regular(path, limit):
    """Refuse symlinks/devices and cap allocation even if a file grows."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input must be a regular file")
        if before.st_size > limit:
            raise ValueError("input exceeds byte limit")
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
        if len(data) > limit or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("input changed or exceeded byte limit")
        return data


def pack(args):
    manifest = {"format_version": 1, "classification": "PRIVATE_REVIEW_REQUIRED",
                "created_unix": int(time.time()), "artifacts": [],
                "limitations": ["No upload, decryption, repair or live DB queries performed.",
                                "Supplied reports may contain private data; review before sharing.",
                                "Database snapshots require their matching WAL and salt if applicable.",
                                "Stable size/mtime does not prove snapshot consistency."]}
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(args.output, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output, tarfile.open(fileobj=output, mode="w:gz") as archive:
            def add(name, data, status=None):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o600
                archive.addfile(member, io.BytesIO(data))
                manifest["artifacts"].append({"name": name, "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(), "status": status or {"available": True}})

            for category, paths in (("forensics", args.forensic_record),
                                    ("integrity", args.integrity_report),
                                    ("migration-ledger", args.migration_ledger),
                                    ("journal", args.journal_file)):
                for index, path in enumerate(paths):
                    add(f"{category}/{index}.txt", read_regular(path, LIMIT), {"available": True, "source_name": path.name})
            if args.database_snapshot:
                for index, path in enumerate(args.database_snapshot):
                    add(f"private-database/{index}.bin", read_regular(path, args.max_database_bytes), {"available": True, "source_name": path.name})
                manifest["contains_database"] = True
            else:
                manifest["contains_database"] = False
            data, status = run_bounded([args.wn_agent, "--version"])
            add("versions/wn-agent.txt", data, status)
            if args.repo:
                data, status = run_bounded(["git", "-C", str(args.repo), "rev-parse", "HEAD"])
                add("versions/git-head.txt", data, status)
            if args.journal_since:
                data, status = run_bounded(["journalctl", "--user", "-u", "wn-agent-hermes.service",
                    "--since", args.journal_since, "--until", args.journal_until,
                    "--no-pager", "-o", "json", "-n", "1000"])
                add("journal/service.jsonl", data, status)
            manifest["coverage"] = {"forensics": bool(args.forensic_record),
                "integrity": bool(args.integrity_report), "migration_ledger": bool(args.migration_ledger),
                "journal": bool(args.journal_file or args.journal_since)}
            raw = json.dumps(manifest, indent=2).encode() + b"\n"
            member = tarfile.TarInfo("manifest.json")
            member.size, member.mode = len(raw), 0o600
            archive.addfile(member, io.BytesIO(raw))
        return manifest
    except BaseException:
        os.unlink(args.output)
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--output", type=Path, required=True, help="New 0600 archive; must not exist")
    for flag in ("forensic-record", "integrity-report", "migration-ledger", "journal-file"):
        result.add_argument("--" + flag, type=Path, action="append", default=[])
    result.add_argument("--database-snapshot", type=Path, action="append", default=[],
                        help="Opt-in: offline snapshot ONLY, never the live database; repeat for sidecars")
    result.add_argument("--confirm-offline-snapshot", action="store_true")
    result.add_argument("--max-database-bytes", type=int, default=256 * 1024 * 1024)
    result.add_argument("--wn-agent", default="wn-agent")
    result.add_argument("--repo", type=Path)
    result.add_argument("--journal-since")
    result.add_argument("--journal-until")
    return result


def main():
    cli = parser()
    args = cli.parse_args()
    if args.database_snapshot and not args.confirm_offline_snapshot:
        cli.error("database inclusion requires --confirm-offline-snapshot")
    if bool(args.journal_since) != bool(args.journal_until):
        cli.error("journal capture requires both --journal-since and --journal-until")
    if not 0 < args.max_database_bytes <= 512 * 1024 * 1024:
        cli.error("database byte limit must be between 1 and 536870912")
    if sum(map(len, (args.forensic_record, args.integrity_report, args.migration_ledger,
                     args.journal_file, args.database_snapshot))) > 32:
        cli.error("at most 32 input files")
    try:
        result = pack(args)
    except (OSError, ValueError) as error:
        cli.exit(1, f"pack failed: {type(error).__name__}; no complete archive produced\n")
    print(json.dumps({"classification": result["classification"],
                      "coverage": result["coverage"], "contains_database": result["contains_database"]}))


if __name__ == "__main__":
    main()
