# Shared-home session corruption, 2026-09-18

Status: hardening implemented; historical page-damage mechanism unresolved;
recovery and manager deployment/live verification remain open.
Tracking: `btq-harness-2e48d60f27b73a1770708fe9`. Maintenance handoff:
`btq-harness-cdd0f89b1227a9f698eebaa2`.

## Evidence and limits

The service journal confirms `sqlcipher_page_cipher hmac check failed` at
13:05:58 PDT on page 9255. The 13:00–13:10 window contains 1,298 deferred-error
entries, not just one every 30 seconds. The reported 37,994,496-byte database
has 9,276 4-KiB pages, consistent with that page number.

The named full pre-repair home backup was absent on the investigation host.
A retained account backup contained an older corrupt snapshot and a later
snapshot. Read-only checks used private copies, with keys derived in memory
from the retained account metadata, signing secret, and matching salt. Keys
and message contents were not printed. Neither snapshot included WAL/SHM;
copy-time consistency is therefore unproven.

| Snapshot | Bytes | SHA-256 | Result |
| --- | ---: | --- | --- |
| Older, September 18 | 37,994,496 | `37d015a92af54d98c2e37912f1bcb37a3bb4075597e0d8dd2376ba3faa0b6e2e` | Structural corruption |
| Later, September 19 | 8,679,424 | `83e2832e1125c8da0177c3b399f86f9d787c9c1829e9d30a66403910bc693398` | Structural corruption |

Both Python SQLCipher 4.12 and MDK's pinned SQLCipher 4.17 reject structural
integrity. Native `quick_check(1)` and `integrity_check(1)` each return a
non-`ok` diagnostic. `cipher_integrity_check` returns no rows; that alone
must not be interpreted as database health. Successful decryption and schema
reads distinguish this from ordinary Python sqlite3's expected inability to
open an encrypted database.

Native full-row sequential reads complete for 76 tables. They stop after
4,189 `app_events` rows and 1,389 `message_timeline` rows in the older snapshot;
the later snapshot yields only 167 and 168 respectively. These are readable
prefix counts, not counts of all recoverable history. Reading a table to its
end is also not proof of relational consistency: the older `cgka_messages`
scan yields 8,429 rows but only 8,427 distinct primary keys and message IDs.
Two primary-key conflicts contain different IDs, states, and payloads.

Two offline encrypted rebuild attempts stopped at those conflicts. The second
allowed only exact duplicate-row elimination and still failed. No row was
arbitrarily selected as authoritative. Partial output databases are **not
restore candidates**. Existing live files were not changed by this work.

A separately retained prior rebuild, `rebuilt6.sqlite` (September 19 11:58,
10,342,400 bytes, SHA-256
`1bfae3a9eb4c34a475040bd2e8c548e0eb7541cc48f1586f6a9e235d83f3406c`),
passes native SQLCipher 4.17 `quick_check(1)` and `integrity_check(1)` with the
later snapshot key. All 78 table scans complete. It contains 894 message rows,
430 app-event rows, no timeline rows, and 208 OpenMLS rows. It is a structurally
valid historical recovery artifact, not a proven lossless recovery or proof of
current live health. A follow-up foreign-key check reports **2,803 violations**,
so this artifact must not be promoted as a verified restore candidate.
Manager reconciliation must establish its origin, whether
it was installed, and application-level validity before any deployment use.

An older plaintext recovery artifact passes SQLite integrity but omits
`app_events` and `message_timeline` entirely; it contains 8,324 message rows.
That artifact and retained rebuilds had 0644 modes and were restricted to 0600
during this investigation. No contents were published or deleted.

No kernel journal entries were available for the incident window. This does
not rule out disk faults. The observed live service had a newer start time
than the incident process, so its current state cannot establish the original
binary cohort. Historical installed hashes, migrations, and prior recovery
actions still need reconciliation by the manager.

## Root-cause assessment

A concrete ownership defect exists independently of the page-level RCA.
`wn-agent` acquires `MarmotRootRuntimeLease`, introduced in #1173, but direct
`wn` and `wnd` constructed the deliberately unleased app entry point. Heavy
CLI usage could consequently open the same root alongside a hydrated connector
runtime. The intended root-wide single-owner invariant was not enforced.

SQLite uses WAL, synchronous FULL, a busy timeout, and connection/transaction
serialization. Those mechanisms protect SQL transactions; they do not make
independent hydrated MLS runtimes safe to mutate the same account. The root
lease closes that unsupported access pattern. This is **not evidence that
ordinary concurrent SQLite writes alone caused an HMAC failure**, nor proof
that this patch repairs previously damaged pages.

Migration/version skew and disk faults cannot be excluded with the available
historical evidence. The babysitter invokes the same CLI binary and is not a
separate SQLCipher-linkage suspect. Current source inspection and current
binary timestamps do not prove which revisions opened the home on September 18.

## Hardening and supported access

Direct CLI execution now takes the root lease before opening app storage,
including fallback after an abandoned implicit daemon socket. Daemon startup
acquires ownership before removing socket/PID artifacts. Socket clients use
the daemon's ownership. Raw QUIC receive and unanchored send commands do not
open account storage and do not acquire a root lease. Internal daemon helpers remain within that process's
lease; this patch does not claim to redesign all in-process runtime scheduling.

Use one owning runtime per root. With `wnd` as owner, CLI clients use its
socket. With `wn-agent` as owner, use supported agent-control operations through
its facade. **`WN_SOCKET` speaks the wnd protocol, not the wn-agent protocol.**
Unsupported administration requires a manager-coordinated offline window or
an isolated home; never bypass the lease or unlink its stable lock file.
Mixed old/new executables remain unsafe because old clients can ignore the
lease. Deploy a coherent cohort and route all senders before relying on it.

Ready account workers run a structural integrity probe on maintenance ticks,
initially after readiness and then at least 120 seconds after the previous
attempt completes. SQLite VM work receives a 250-ms interruption budget;
connection waits and filesystem I/O are not preemptible. Scheduling delays,
stopped workers, and accounts that cannot reach readiness limit coverage.
A budget overrun or any other incomplete probe is unknown health, never success.
The probe does not repair data, reopen storage, run migrations, or claim full
index, foreign-key, or MLS consistency coverage.

Alerts use fixed fields only: target `marmot_app::storage_integrity`, method
`periodic_probe`, and status `corrupt` (error), `incomplete` (warning), or
`healthy` (info, a completed structural probe only).
Maintenance monitoring must route these categories and detect missing checks;
a fresh gateway heartbeat is insufficient. No raw SQLite diagnostic row, SQL,
account identifier, message, path, or key enters the alert.

## Recovery and deployment handoff

Deployment handled by manager. Deployable work remains open until merged,
deployed, and live-verified, with evidence recorded on the Bead.

1. Locate a coherent full backup and establish the previous repair history.
   Preserve original files, salts, account secrets, and contemporaneous WAL/SHM.
   Stop every owner before taking a filesystem snapshot or restoring a root.
2. Work on restricted offline copies with the matching key and compatible
   SQLCipher version. Require full structural and foreign-key checks plus
   application-level MLS/group validation. Do not run forward migrations against
   the only retained copy or combine unrelated salts, keys, databases, or WALs.
3. Prefer a verified coherent restore. Available snapshots support partial
   history investigation but not a proven lossless restore. A fresh session
   cannot reconstruct private MLS ratchets from public relay history alone;
   authenticated group recovery/rejoining may be necessary and older history
   may remain unavailable. Resolve conflicting records explicitly before use.
4. Retain a rollback home, deploy the reviewed matching binary/integration
   cohort, route all automation through its owning socket facade, and restart.
   Verify an actual outbound delivery, inbound receipt, loaded-account storage
   health, and absence of renewed corruption. Record merge SHA, installed hashes,
   start time, routing inventory, and live evidence without message contents.

The storage tests cover healthy checks, interruption and subsequent connection
reuse, constraint failures, and damaged encrypted pages. CLI subprocess tests
cover ownership rejection, abandoned-socket fallback, release/reacquisition,
and preserving another owner's socket artifact.
