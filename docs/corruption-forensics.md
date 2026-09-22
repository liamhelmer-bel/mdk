# Corruption evidence capture

This delta is based on `28db7b3b`. It does not duplicate PR #1937 or change its
root-lease policy. The fetched origin corruption branch was reviewed at
`ab72e9e5e30a6b51a0b1af665ba6ee9a8cffe450`.

## Reuse and integration

PR #1937 owns `SqliteAccountStorage::probe_integrity` and the loaded-account
worker's 120-second scheduler with a 250-ms SQLite VM budget. Its health states
are healthy, corrupt and incomplete. Reuse that implementation; do not install
a second timer. A VM budget does not preempt filesystem I/O or connection waits.

After integrating that PR, change its `probe_integrity` wrapper to retain the
result and call `connection.record_integrity_failure()` when it is
`IntegrityProbe::Corrupt`, before returning it. This captures structural failures
reported as diagnostic rows as well as native SQLite errors. This integration
is intentionally not applied to this branch, which lacks PR #1937. Periodic
structural detection remains dependent on that PR and this small wiring change.
The task evidence bundle includes `pr1937-forensic-wiring.patch` against the
surveyed head; manager integration must apply and validate it with both changes.

## Local recorder

On release of a live `ConnectionGuard`, storage records the scope duration and
SQLite extended result code. CORRUPT, NOTADB and IOERR trigger a best-effort local
record, limited to once per database pathname per process per minute. The
process-wide admission table is bounded to 256 entries, failing closed when
full; path aliases and separate processes are separate rate-limit domains.
NOTADB is unreadable/wrong-key evidence, not proof of corruption.

The latest record replaces `<database>.forensics.json` atomically through an
exclusive 0600 temporary file. It holds the last 32 connection scope timings,
not individual statement timings or SQL text. It includes wall time, PID,
file sizes/mtime, WAL/SHM metadata, startup schema/migration/version metadata,
and a bounded best-effort Linux `/proc` descriptor-owner snapshot. Kernel
page numbers and per-file disk error counters are explicitly unavailable;
SQLCipher's own incident journal may supply the former. Cached schema/migration
metadata is labeled with its capture point and is not a live ledger dump.

Tracing uses only the fixed `storage_sqlite::forensics` target, `capture`
method, numeric SQLite code and evidence-save boolean. Paths and descriptor
owners occur only in the private local file. There are no SQL statements,
parameters, row values, keys or salts in the recorder. The connection is never
reopened to collect metadata; doing so can release POSIX locks. Filesystem
metadata/readlink calls do not open a database descriptor.

Coverage limitations: the final SQLite result code can be overwritten by a
later successful operation on the same guard. Account open-time key-validation,
operational-pragma and migration failures also have a query-free capture hook. Other raw, unwrapped connections remain outside the
guard path. Structural failures returned as rows need
the explicit hook above. This is not an assertion of complete codec interception.
Artifact publication and process inspection are synchronous best-effort work
on the error path; entry counts and a 50-ms between-entry inspection budget are
bounded, but kernel/filesystem calls cannot be preempted. Disk-full or permission
failure leaves `evidence_saved=false`; the original storage result is unchanged.
A crash may leave the private temporary file and prevent another publication
for that PID. A single latest record is retained, not an unbounded incident log.

## Private pack collection

Run `python3 scripts/corruption-pack.py --help`. Example against staged reports:

```sh
python3 scripts/corruption-pack.py --output /tmp/corruption-private.tar.gz \
  --forensic-record /tmp/staged/session.sqlite.forensics.json \
  --integrity-report /tmp/staged/integrity.json \
  --migration-ledger /tmp/staged/migrations.json \
  --journal-file /tmp/staged/incident.jsonl --repo .
```

The output must not exist; it is created 0600. Inputs must be regular files,
not symlinks or FIFOs. The archive uses generated member names, fixed modes and
SHA-256 manifests. Default inclusion excludes databases. Missing report classes
and unavailable version commands remain explicit in the manifest. Optional
journal capture requires both bounds and caps entries, bytes and command time.
The pack performs no live SQLite queries, decryption, repair, service changes
or upload. Its reports and raw journal may contain private data: the entire
archive is marked `PRIVATE_REVIEW_REQUIRED`, never automatically public-safe.

To include an operator-provided offline database snapshot, pass
`--database-snapshot PATH --confirm-offline-snapshot`; repeat for necessary
sidecars. Maximum input count is 32; reports are capped at 4 MiB and databases
at 256 MiB by default (hard ceiling 512 MiB). Capture size/mtime stability is
checked, but it does not prove snapshot consistency. Use a coordinated offline
snapshot or an owning-runtime backup, not a raw copy of a live WAL database.
Never include keys. Review salt, identifiers and all reports before sharing.

Deployment is handled by manager with the PR #1937 and SQLite lock-fix cohort.
The upstream issue text is drafted separately; private artifacts require review
before attachments are selected.

## Validation scope

The encrypted forensic regressions cover damaged-page capture, wrong-key
classification, rate limiting, private publication, bounded history and POSIX
lock preservation. Pack tests exercise the actual CLI's offline opt-in boundary,
verify included snapshot bytes against the manifest SHA-256, and reject input
symlinks/FIFOs and oversized or failed inputs. Staged reports are synthetic;
passing these checks does not validate an incident snapshot or complete the
PR #1937 integration. See the task evidence for exact commands and full-suite
completion status.
