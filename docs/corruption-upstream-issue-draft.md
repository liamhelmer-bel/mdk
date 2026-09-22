# Draft: SQLCipher HMAC failure and structural corruption in shared Marmot home

This is a draft for marmot-protocol/mdk, not a filed issue. No private database,
key, salt, journal or forensic archive is attached.

On September 18, 2026 at 13:05:58 PDT, the retained wn-agent journal reported a
SQLCipher HMAC failure on page 9255. The prior incident investigation records
1,298 deferred-error entries during 13:00–13:10. A 37,994,496-byte snapshot has
9,276 4-KiB pages, consistent with the reported page index.

Provenance: these incident observations are from
`docs/incident-2026-09-18-session-corruption.md` on the PR #1937 branch at
`ab72e9e5e30a6b51a0b1af665ba6ee9a8cffe450`, rather than newly repeated live-home
checks. The named full pre-repair home backup was absent during that inquiry.
Two retained snapshots failed native SQLCipher 4.17 structural checks. They
lacked WAL/SHM, so copy-time consistency was not established. An empty
`cipher_integrity_check` result did not establish structural health. Partial
rebuild artifacts are not validated restore candidates.

The historical page-damage mechanism remains unresolved. The root-ownership
bypass addressed in PR #1937 and the separately reproduced POSIX lock-loss bug
are concrete defects, but neither alone proves the historical HMAC failure's
cause. Installed binary provenance and disk-fault evidence at incident time
are incomplete. Current binary hashes cannot reconstruct historical deployment.

The companion instrumentation delta captures bounded local metadata on storage
failures, and the evidence-pack tool hashes and packages explicitly supplied
reports with clear coverage gaps. PR #1937 remains the periodic probe owner.
The resulting archive is private by default; review is required before any
public attachment. The instrumentation WIP is signed commit `7ab46023`, based on `28db7b3b`.
It has not been deployed; deployment is handled by manager.

## Reproduction and validation

The historical incident is not deterministically reproduced. The instrumentation
regressions instead create an encrypted fixture, damage an encrypted page after
closing the connection, reopen it with the fixture key and verify private
forensic publication. Separate regressions cover wrong-key classification and
preservation of SQLite's reserved POSIX lock against another process.

```sh
cargo test -p storage-sqlite forensics::tests --locked
python3 -m unittest discover -s scripts/tests -p test_corruption_pack.py
just --tempdir /tmp fast-ci
```

Worker evidence records five forensic regressions passing and fast-ci passing
against the WIP source. The pack suite has four test cases, including real CLI
rejection without offline-snapshot confirmation and archive hash verification
after explicit opt-in. The full storage suite remains pending; this draft does
not claim complete workspace test parity.

## Evidence available and missing

The private pack format records SHA-256 hashes, supplied-report coverage and
version-command failures. Staged pack validation used synthetic reports and the
installed binary's version, not the incident database. No incident archive is
attached or represented as public-safe. The retained incident snapshots and
journal require private review before sharing.

Unavailable historical evidence includes a demonstrated consistent pre-failure
snapshot, exact writer overlap at the failure, and contemporaneous host disk
error counters. The new recorder cannot recover those facts retroactively.
PR #1937's probe must be integrated with the forensic hook before periodic
structural failures produce the new record; no second scheduler is introduced.

## Requested maintainer guidance

Can maintainers identify additional SQLCipher-safe metadata that would help
distinguish page damage, wrong-key/key-lifecycle problems and inconsistent
snapshot artifacts without reopening the live database or logging private
values? Is there a supported connection-local diagnostic callback for the
failing page number that avoids global logging of SQLCipher error text?

Please advise on a private channel for any encrypted snapshot or journal
exchange. This report does not attribute the historical incident to a specific
change without further evidence.
