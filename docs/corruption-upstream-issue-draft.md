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
public attachment. Validation results and the final delta commit should be
added to this draft once the implementation has passed its checks.
