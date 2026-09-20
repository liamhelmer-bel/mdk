# CLI QUIC corruption investigation, 2026-09-20

Tracking: `btq-harness-1bdb3731fe305e6aee3210e3`.
Investigated revision: `28db7b3bffe01eed7c8c61f0984d253a6a755213`.

## Findings

A concrete, independently reproduced lock-safety defect exists in
`fs_private::ensure_private_db_files`. It opens and closes existing database
and sidecar files outside SQLite. On this Linux host, those closes release
POSIX locks held by another connection in the **same process**. An encrypted
SQLCipher WAL experiment allowed a second process to commit while the first
process still had an uncommitted write transaction.

This is not yet proof that the helper caused the historical QUIC test failure.
The original disposable database was not retained in the supplied evidence,
and its error has no database category, operation, extended result code, or page
number. The specific damaged page and the ordering that damaged it remain
unknown. Keep the original integration result **failed with a passing isolated
rerun**, not “known flaky” or “passed.”

No product implementation, live-home inspection, repair, or deployment was
performed for this research. Deployment handled by manager.

## Original failure and execution path

The original four-package command was:

```sh
cargo test -p wn-cli -p agent-connector -p agent-control -p marmot-app \
  --features wn-cli/test-policy-overrides -- --test-threads=2
```

It used the run's shared `CARGO_TARGET_DIR`. CLI integration reported 103 passed,
1 failed, exit 101. The failing test was
`stream_start_quic_chunks_and_final_payload_verify_through_mls_messages`.
The later isolated CLI-only rerun passed in 12.14 seconds. It neither repairs
that result nor establishes why the earlier run failed.

At the investigated revision:

- `crates/cli/tests/cli.rs:3905` creates Alice and Bob in one temporary home.
  Bob's long-running `stream watch` overlaps `stream send --start-event-id`.
- `run_json_until_child_exits` retries failed sends but does not repeat a
  successful send. It waits for and collects the watcher before returning.
  The subsequent `stream finish` failed, after both overlapping commands exited.
- `execute_inner` in `crates/cli/src/lib.rs` bypasses app setup only for raw
  receive and **unanchored** send. Anchored send and watch construct an app.
  `app_for_role` uses the externally coordinated, unleased constructor.
- `agent_text_stream_crypto_for_start_event` in
  `crates/marmot-app/src/runtime/agent_stream_watch.rs` reads messages, loads
  group state and exporter state, and attaches a persistent publisher sequence
  store. Without an account selection it searches local signing accounts.
  An apparently transport-only anchored send therefore accesses storage.
- `stream finish` calls `app.status` and then `finish_agent_text_stream`.
  Its outer JSON error does not tell which operation failed.

The recorded response was `engine_error` with
`backend corruption: database disk image is malformed`. The SQLite mapping in
`crates/storage-sqlite/src/codec.rs:232` classifies `DatabaseCorrupt` as
`StorageError::Corruption`; busy/locked errors have a separate classification.
`crates/traits/src/storage.rs` supplies the “backend corruption” display prefix;
`crates/cli/src/error.rs` supplies the generic engine JSON envelope. This is
storage corruption reporting, not a QUIC transcript-verification failure or
ordinary busy timeout. It does not by itself identify a physical file.

## Reproduced descriptor-close defect

`crates/fs-private/src/lib.rs:846` calls `ensure_private_file` for the database
and `tighten_existing_private_file` for `-wal`, `-shm`, and `-journal`.
Each opens a descriptor, applies permissions, and drops that descriptor.
The encrypted storage opener calls this helper **on every open**, before
`rusqlite::Connection::open` (`crates/storage-sqlite/src/connection.rs:1029`).
Other call sites include shared storage, projection storage, and both encrypted
and legacy directory caches. Reopening a file while the same process already
has SQLite connections is therefore a dangerous case to audit.

SQLite documents this exact class of hazard: an unrelated descriptor close
can discard the process's POSIX locks without SQLite knowing. SQLite's own
connection handling coordinates its closes; independent file-handling code
does not participate in that coordination. See
[SQLite: POSIX locks canceled by close](https://www.sqlite.org/howtocorrupt.html).

The tests used the actual Rust helper from this checkout, compiled as a tiny
research-only shared library, not a replacement Python implementation.

| Disposable probe | Before helper | After helper |
| --- | --- | --- |
| Independent POSIX lock attempt on main DB | Blocked | Acquired |
| Same test on WAL, SHM, journal, each separately | Blocked | Acquired |
| Plain SQLite 3.45.1 WAL second writer | Database locked | Committed |
| SQLCipher 4.17.0 / SQLite 3.53.3 encrypted WAL second writer | `SQLITE_BUSY` (5) | Success (0) |

In both SQLite probes the first connection still reported an active transaction.
The encrypted probe linked SQLCipher and OpenSSL static archives already in the
host's Cargo build cache, exposed through a separate probe shared library. It
queried the native library versions; it did not use Python's plaintext sqlite3
module. This establishes loss of write exclusion, not reproduction of the
original malformed-page error. The archives were not independently proven to
be the exact objects linked into the historical test executable.

A separate process calling the permission helper cannot cancel another
process's locks. The necessary condition is a helper close in the process
that owns those locks, followed by a conflicting access elsewhere. Establishing
that exact ordering in the original QUIC test requires further instrumentation.

## Relationship to PR #1937

PR #1937 adds direct-CLI/daemon root ownership enforcement. Its `ca267b5b`
change gives Alice and Bob separate homes in this QUIC test. Its later
`ab72e9e` change adds the approved startup-only TUI lease check. Neither changes
`fs-private` relative to this investigation's base.

Separate homes and root ownership remove unsupported cross-process app usage.
They are useful hardening, but should not be presented as a fix for descriptor
closes while SQLite connections remain open. The existing PR's passing CLI
suite also tests a different home layout. Do not duplicate or rewrite its
implementation under this research Bead.

## Reproduction results

The exact four-package command was repeated on the clean original revision,
using two test threads and the same Cargo cache location. Final result is
recorded in the research evidence accompanying this document.

Resolved Cargo feature comparison for combined versus CLI-only invocations
found `tokio` additionally enabled `process,test-util`, and `zerocopy`
additionally enabled `derive,zerocopy-derive`. No resolved rusqlite or
libsqlite3-sys feature difference was found. This narrows the build-context
uncertainty; it does not establish identical scheduling or historical binaries.

## Proposed follow-up

Queued proposal: `btq-harness-6f5254aba271a0bb120dbb0e`.

Authorize a separate fix for database/sidecar permission handling. Preserve
restrictive creation, symlink protections, and existing-file safety without
opening and closing descriptors behind active SQLite connections. Design must
cover concurrent openers and cross-instance same-process use; a mutex around
permission operations alone does not protect the lifetime of SQLite locks.
Do not replace descriptor handling with an unchecked path-based chmod or remove
permission hardening merely to make the probe pass.

Acceptance should include actual encrypted SQLCipher WAL subprocess tests:
first writer remains protected across a second storage open/permission pass;
second writer is busy until commit/rollback, then succeeds; fresh and legacy
file modes and symlink rejection remain correct. Cover main DB and SHM locks,
all helper call sites, full relevant suites, and isolated-home dogfooding.

Separately, add bounded failure capture to the disposable QUIC test workflow:
preserve a coherent private home only after its children exit, record binary
hashes/features and aggregate operation/category/SQLite result codes, then run
native offline integrity checks. Do not upload secrets or raw account/message
identifiers. Repeated matched-context runs and controlled same-home/separate-home
comparisons can then discriminate the lock defect from other causes.

## Evidence and reproducer

Host-local original logs (unmodified):

- `/tmp/mdk-combined-rust-tests.log`, SHA-256
  `74e9f55ef7304fa5b27ac89a46173e19b972d9ab3a8709096c8e7f2a2fce67b8`.
- `/tmp/mdk-combined-quic-rerun.log`, SHA-256
  `0c4f0b3c97866aefd4f79899af3986d40460b6ba5df2796654f696b436b37593`.

New logs: `/tmp/mdk-1bdb-original-context.log`,
`/tmp/mdk-1bdb-lock-probe.log`, `/tmp/mdk-1bdb-native-lock-probe.log`, and
`/tmp/mdk-1bdb-native-durable-probe.log`. Feature inventories use the
`/tmp/mdk-1bdb-{combined,cli}-{features,resolved}.txt` names.

The committed [helper](sqlite-lock-probe/helper.rs) and
[encrypted probe](sqlite-lock-probe/probe.py) use disposable files only.
To reproduce on Linux:

1. Compile `helper.rs` as a Rust `cdylib` in a temporary Cargo package with a
   path dependency on this checkout's `crates/fs-private`.
2. Link the build's SQLCipher archive into a shared library with its matching
   OpenSSL crypto archive, `-ldl -lpthread -lm`, using `--whole-archive` around
   SQLCipher so its C API is exported.
3. Set `PROBE_HELPER_LIBRARY` and `PROBE_SQLCIPHER_LIBRARY` to those absolute
   shared-library paths, then run `python3 docs/research/sqlite-lock-probe/probe.py`.

The probe prints native versions, before/after result codes, and whether the
first transaction remains open. Its key and rows are synthetic. It does not
connect to relays, open a live home, or attempt data recovery. A fixed helper
should keep the second writer busy in both attempts.
