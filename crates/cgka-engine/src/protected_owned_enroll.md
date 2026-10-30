# Fresh-only native receiver enrollment — source qualification

This fixed Linux `heterodyne-protected-receiver-enroll` entry takes no arguments
and imports no Welcome, approval or native-state JSON from its caller. Its root
profile selects an exact account/group/operator policy/storage generation and
finite inbox wait. The actual SDK inbox supplies the original transport Welcome;
`Engine::receiver_join_owned` captures provenance at the real authenticated join
commit seam. Initial native-state and Welcome provenance hashes are computed from
that capture. A supplied hash cannot substitute for native join evidence.

The private fixed descriptors are: 3 root-owned read-only mode0400 closed JSON
profile; 4 account secret; 5 SQLCipher key; 6 fresh empty journal; 7 journal
directory; 8 storage lease; 9 fresh empty anchor; 10 anchor directory; 11 exclusive
fresh empty join intent; 12 intent directory; 13 existing protected account
directory; 14 connected authenticated Unix consumer. Keys are exact32bytes in
read-only mode0400 files. The account database must already exist mode0600 with
receiver owner under its mode0700 directory, contain native KeyPackage provisioning,
and have no groups or pending application events. This entry does not provision
an account, publish KeyPackages, create an invite or enroll historical joins.

Schema `heterodyne-protected-receiver-fresh.v1` has only `receiver_uid`,
`consumer_uid`, `account`, `group`, `operators`, `storage_generation`, `endpoints`,
`wait_seconds` and `schema`. Account/generation/operator hashes and group encoding
reuse existing native validation; duplicates/self operators refuse. Consumer UID
must be nonzero and distinct from the receiver UID. Exact original
profile bytes determine source_profile_sha256. The root publisher must retain
those bytes and enforce actual policy/enrollment custody. No publisher is installed.

All slots are owned before Tokio allocates descriptors. The storage lease is held
before encrypted SQLite opening; nofollow database identity is checked before/after
open. Empty journal/anchor descriptor properties, locks and directory fsyncs are
preflighted before native join. The original Welcome intent is durable before
KeyPackage consumption. Exact native join evidence is then bound into a newly
fsynced header/independent-anchor mechanics and retained original-join record before
positively acknowledging the singleton matching native GroupJoined. Missing durable
write, wrong actual group, or partial/unknown effects retain pending evidence and
refuse. They never retry, reset state or manufacture enrollment. SDK activation is
bounded30seconds, finite wait1..86400seconds, SDK shutdown5seconds. Notification loss
or shutdown refuses positive output. Individual invalid relay DTOs use the reviewed
receiver forwarding behavior. The anonymous ephemeral disk FIFO is opened
through the already retained private journal-directory FD and has no directory
entry or added inherited slot. It is nonauthority storage and makes no restart
promise; SDK lag or I/O failure still holds.

The consumer sends32 fresh nonce bytes on the kernel-checked Unix stream. After
positive native enrollment, the response is the same bounded u32-BE framed compact
JSON with schema `heterodyne-owned-fresh-enrollment.v1`, nonce_hex,
startup_profile_sha256, actual derived enrollment, actual header_record,
header_sha256 and actual journal checkpoint. It is an enrollment correlation
response, not approval or deployment permission. Lost output remains UNKNOWN;
subsequent root-side recovery must inspect protected original evidence and must
not rerun this fresh-only entry. The separately owned consumer must retain nonce,
source child/UID/profile and original evidence; no JSON authority importer exists.

Actual causal source tests use real native MLS and existing fixture passthrough
transport, not actual NIP59 relay/account custody. They prove derived enrollment,
retained original then positive ack/reopen, pre-effect nonempty-anchor/invalid-policy
refusal, wrong group UNKNOWN retention and actual read-only journal write failure
without native acknowledgment. They do not qualify a complete installed SDK+
encrypted account+fresh Welcome+protected publisher/consumer lifecycle.

The mutable anchor descriptor remains source-only durability mechanics. The current
approved independent guarded-consumer custody is not implemented by a separate file
or backup exclusion alone. The proposed descriptor-custody amendment has separate
review/human approval requirements; this source neither implements nor claims that
amendment. Root publisher, actual KeyPackage/account provisioning, independent anchor
custody, immutable source/runtime installation and separate live enrollment/deployment
approval remain prerequisites. Existing unknown historical joins remain UNKNOWN.
