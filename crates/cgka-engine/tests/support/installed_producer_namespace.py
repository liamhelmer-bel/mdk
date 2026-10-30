import argparse
import base64
import ctypes
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import time

parser = argparse.ArgumentParser(
    description="Disposable namespace qualification only; not installed authority"
)
parser.add_argument("--test-binary", type=pathlib.Path, required=True)
parser.add_argument("--product", type=pathlib.Path, required=True)
parser.add_argument("--purelib", type=pathlib.Path, required=True)
parser.add_argument("--native-fixture", type=pathlib.Path, required=True)
args = parser.parse_args()
# Refuse execution outside a disposable user/mount/network namespace before any
# mount or path mutation. Namespace root must map to an unprivileged host UID.
uid_map = [
    list(map(int, row.split()))
    for row in pathlib.Path("/proc/self/uid_map").read_text().splitlines()
]
if os.geteuid() != 0 or not any(a == 0 and b != 0 and n == 1 for a, b, n in uid_map):
    raise RuntimeError("requires isolated namespace root mapped to nonroot host UID")
for kind in ("mnt", "net"):
    with open(f"/proc/self/ns/{kind}", "rb") as namespace:
        owner_fd = fcntl.ioctl(namespace.fileno(), 0xB701)  # Linux NS_GET_USERNS
        try:
            if os.fstat(owner_fd).st_ino != os.stat("/proc/self/ns/user").st_ino:
                raise RuntimeError(
                    "namespace must be owned by this disposable user namespace"
                )
        finally:
            os.close(owner_fd)
if sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
    raise RuntimeError("requires isolated loopback-only network namespace")
PRODUCT = args.product.resolve()
PURELIB = args.purelib.resolve()
NATIVE = args.native_fixture.resolve()
TEST = args.test_binary.resolve()
for checkout, head in [
    (PRODUCT, "faec83f17b92d3251e3118942c982661b085be59"),
    (NATIVE, "fa1c616331e8b94fc593c25b7c59f12a7dbe40d9"),
]:
    actual = (
        subprocess.check_output(
            ["/usr/bin/git", "-C", str(checkout), "rev-parse", "HEAD"]
        )
        .decode()
        .strip()
    )
    clean = subprocess.check_output(
        [
            "/usr/bin/git",
            "-C",
            str(checkout),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ]
    )
    if actual != head or clean:
        raise RuntimeError("qualification checkout source pin/cleanliness")
libc = ctypes.CDLL(None, use_errno=True)


def mount(src, dst, kind=None, flags=0, data=None):
    if libc.mount(
        os.fsencode(src) if src else None,
        os.fsencode(dst),
        os.fsencode(kind) if kind else None,
        ctypes.c_ulong(flags),
        os.fsencode(data) if data else None,
    ):
        raise OSError(ctypes.get_errno(), "mount " + str(dst))


def run(argv, **kw):
    return subprocess.run(argv, check=True, capture_output=True, **kw).stdout


mount(None, "/", flags=(1 << 14) | (1 << 18))
mount("tmpfs", "/opt", "tmpfs", data="size=512m,mode=0755")
f = pathlib.Path("/opt/producer-qualification")
f.mkdir(mode=0o755)
shutil.copytree(
    PRODUCT / "src", f / "src", ignore=shutil.ignore_patterns("__pycache__")
)
(f / "purelib").mkdir()
shutil.copytree(
    PURELIB / "msgspec",
    f / "purelib/msgspec",
    ignore=shutil.ignore_patterns("__pycache__"),
)
(f / "python/bin").mkdir(parents=True)
shutil.copyfile("/usr/bin/python3.12", f / "python/bin/python3")
(f / "python/bin/python3").chmod(0o555)
shutil.copytree(
    "/usr/lib/python3.12",
    f / "python/lib/python3.12",
    ignore=shutil.ignore_patterns("__pycache__"),
)
shutil.copyfile(TEST, f / "native-test")
(f / "native-test").chmod(0o555)
sys.path.extend([str(f / "src"), str(f / "purelib")])
import msgspec
from heterodyne.actions.codec import encode_record
from heterodyne.actions.deployment import Release, Target
from heterodyne.actions.deployment import digest as release_digest
from heterodyne.actions.deployment_outage import decode_packet, packet_digest
from heterodyne.marmot.nip19 import hex_to_npub

v = json.loads(
    (NATIVE / "crates/cgka-engine/src/protected_owned_fixture.json").read_text()
)["output"]
original = base64.b64decode(v["operation_original"])
raw = json.loads(original)
now = time.time_ns()
raw["release"]["not_before_ns"] = now - 1_000_000_000
raw["release"]["deadline_ns"] = now + 60_000_000_000
raw["release"]["recovery"]["deadline_ns"] = now + 120_000_000_000
raw["outage"]["not_before_ns"] = now
raw["outage"]["deadline_ns"] = now + 50_000_000_000
raw["outage"]["recovery_deadline_ns"] = now + 120_000_000_000
raw["outage"]["release_sha256"] = release_digest(
    msgspec.convert(raw["release"], type=Release)
)
original = json.dumps(raw, indent=2).encode()
target = msgspec.convert(raw["release"]["target"], type=Target)
packet = decode_packet(original, (target,))
body = encode_record(packet)
(f / "original.json").write_bytes(original)
repo = f / "repo"
repo.mkdir()
(repo / "docs").mkdir()
(repo / "docs/release.json").write_bytes(body)
env = {
    "PATH": "/usr/bin:/bin",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_NO_REPLACE_OBJECTS": "1",
}


def git(*args):
    return run(
        ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
        env=env,
    )


git("init", "-q")
git("add", "docs/release.json")
git(
    "-c",
    "user.name=Disposable fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-qm",
    "Synthetic qualification packet",
)
commit = git("rev-parse", "HEAD").decode().strip()
(f / "archive.tar").write_bytes(git("archive", "--format=tar", "HEAD"))
(f / "commit.object").write_bytes(git("cat-file", "commit", "HEAD"))
url = (
    "https://github.com/Epiphytic/heterodyne-metaharness/blob/"
    + commit
    + "/docs/release.json"
)
profile = {
    "schema": "heterodyne-owned-card-profile.v1",
    "operation_original_sha256": hashlib.sha256(original).hexdigest(),
    "packet_sha256": packet_digest(packet),
    "group_hex": "91" * 16,
    "publication_url": url,
    "targets": [raw["release"]["target"]],
}
(f / "profile.json").write_text(json.dumps(profile))
for name in ["profile.json", "archive.tar", "commit.object", "original.json"]:
    (f / name).chmod(0o400)
manifest = []
for parent in [f / "src", f / "purelib", f / "python"]:
    for p in sorted(parent.rglob("*")):
        if p.is_file():
            if p.is_symlink():
                raise RuntimeError("fixture closure symlink " + str(p))
            manifest.append([str(p), hashlib.sha256(p.read_bytes()).hexdigest()])
(f / "closure.json").write_text(json.dumps(manifest))
(f / "closure.json").chmod(0o444)
# Full /home overlay prevents any live settings/key access, including owner-only ancestors.
mount("tmpfs", "/home", "tmpfs", data="size=4m,mode=0755")
config = pathlib.Path("/home/openclaw/.config/heterodyne")
config.mkdir(parents=True)
(config / "config.toml").write_text(
    '[platform]\nos="linux"\nservice_manager="systemd"\nsandbox="bubblewrap"\n[profiles.admin]\nadapter="claude-code"\nmodel="fixture"\n[admind]\nprofile="admin"\nchunk_chars=4000\n[admind.marmot]\nrelays=["ws://127.0.0.1:1"]\n'
)
(config / "policy.toml").write_text(
    'approvers=["op"]\noperators=["op"]\n[identities.op]\nmarmot_npub="'
    + hex_to_npub("01" * 32)
    + '"\n'
)
for p in [config / "config.toml", config / "policy.toml"]:
    p.chmod(0o444)
mount("tmpfs", "/run", "tmpfs", data="size=4m,mode=0755")
scratch = pathlib.Path("/run/heterodyne-deploy-publication")
scratch.mkdir(mode=0o700)
os.chown(scratch, 1, 1)
hosts = f / "hosts"
hosts.write_text("127.0.0.1 localhost raw.githubusercontent.com\n")
hosts.chmod(0o444)
cert = f / "ca.crt"
key = f / "ca.key"
run(
    [
        "/usr/bin/openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=raw.githubusercontent.com",
        "-addext",
        "subjectAltName=DNS:raw.githubusercontent.com",
        "-keyout",
        str(key),
        "-out",
        str(cert),
    ]
)
cert.chmod(0o444)
key.chmod(0o400)
mount(hosts, "/etc/hosts", flags=4096)
mount(cert, "/etc/ssl/certs/ca-certificates.crt", flags=4096)
run(["/usr/sbin/ip", "link", "set", "lo", "up"])
assert len(socket.if_nameindex()) == 1
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 443))
listener.listen(1)
listener.settimeout(35)
server = os.fork()
if server == 0:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        conn, _ = listener.accept()
        with ctx.wrap_socket(conn, server_side=True) as c:
            request = c.recv(4096)
            expected = (
                "GET /Epiphytic/heterodyne-metaharness/"
                + commit
                + "/docs/release.json "
            ).encode()
            assert request.startswith(expected)
            c.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
        os._exit(0)
    except (OSError, AssertionError):
        os._exit(1)
try:
    started = time.monotonic()
    child = subprocess.Popen(
        [
            str(f / "native-test"),
            "unchanged_installed_producer_real_tls_then_real_mls_exchange",
            "--ignored",
            "--nocapture",
        ],
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 35
    prepared = False
    while child.poll() is None:
        request = scratch / "group-request"
        if request.exists() and not prepared:
            group = request.read_text()
            assert len(group) == 32 and all(c in "0123456789abcdef" for c in group)
            profile["group_hex"] = group
            with (f / "profile.json").open("w") as stream:
                stream.write(json.dumps(profile))
                stream.flush()
                os.fsync(stream.fileno())
            (scratch / "profile-ready").write_bytes(b"test-only")
            (scratch / "profile-ready").chmod(0o444)
            prepared = True
        if time.monotonic() > deadline:
            child.kill()
            raise TimeoutError("bounded actual combined fixture")
        time.sleep(0.005)
    out, err = child.communicate(timeout=2)
    result = {
        "exit_code": child.returncode,
        "stdout": out.decode(errors="replace"),
        "stderr": err.decode(errors="replace"),
        "elapsed_seconds": time.monotonic() - started,
        "native_test_sha256": hashlib.sha256(
            (f / "native-test").read_bytes()
        ).hexdigest(),
        "closure_entries": len(manifest),
        "closure_sha256": hashlib.sha256((f / "closure.json").read_bytes()).hexdigest(),
        "publication_commit": commit,
        "publication_canonical_sha256": hashlib.sha256(body).hexdigest(),
        "namespace_root_uid": os.getuid(),
        "namespace_opt_uid": f.parent.stat().st_uid,
        "host_usr_mapped_uid": pathlib.Path("/usr").stat().st_uid,
        "synthetic_ca_dns_git_profile": True,
        "installed_authority": False,
    }
    if (scratch / "qualification-output.json").exists():
        result["producer"] = json.loads(
            (scratch / "qualification-output.json").read_text()
        )
    print(json.dumps(result, sort_keys=True))
    assert child.returncode == 0
finally:
    try:
        os.kill(server, 9)
    except ProcessLookupError:
        pass
    os.waitpid(server, 0)
    # Mount namespace exits discard all overlays; no shared mount/host metadata changed.
