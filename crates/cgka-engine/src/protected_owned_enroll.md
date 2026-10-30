# Fresh-only native receiver enrollment — source qualification

This fixed Linux `heterodyne-protected-receiver-enroll` entry takes no arguments
and imports no Welcome, approval or native-state JSON from its caller. Its root
profile selects an exact account/group/operator policy/storage generation and
finite inbox wait and exact native KeyPackageRef. The actual SDK inbox supplies
the original transport Welcome; `Engine::receiver_join_enrolled` captures
provenance at the real authenticated join commit seam. Initial native-state and
Welcome provenance hashes are computed from that capture. A supplied hash cannot
substitute for native join evidence.

The private fixed descriptors are: 3 root-owned read-only mode0400 closed JSON
profile; 4 account secret; 5 SQLCipher key; 6 fresh empty journal; 7 journal
directory; 8 storage lease; 9 fresh empty anchor; 10 anchor directory; 11
exclusive fresh empty join intent; 12 intent directory; 13 existing protected
account directory; 14 connected authenticated Unix consumer; 15 private
ephemeral cache directory on a different filesystem from every durable journal,
anchor, intent and account file/directory. Keys are
exact32bytes in read-only mode0400 files. The account database must already
exist mode0600 with receiver owner under its mode0700 directory, contain native
KeyPackage provisioning, and have no groups or pending application events. This
entry does not provision an account, publish KeyPackages, create an invite or
enroll historical joins.

Schema `heterodyne-protected-receiver-fresh.v1` has only `receiver_uid`,
`consumer_uid`, `account`, `group`, `operators`, `storage_generation`,
`key_package_ref`, `endpoints`, `wait_seconds` and `schema`.
Account/generation/operator hashes and group encoding reuse existing native
validation; duplicates/self operators refuse. Consumer UID must be nonzero and
distinct from the receiver UID. Exact original profile bytes determine
source_profile_sha256. The root publisher must retain those bytes and enforce
actual policy/enrollment custody. No publisher is installed.

All slots are owned before Tokio allocates descriptors. The storage lease is
held before encrypted SQLite opening; nofollow database identity is checked
before/after open. Empty journal/anchor descriptor properties, locks and
directory fsyncs are preflighted before native join. Intent/journal/anchor must
be nonappend O_RDWR descriptors; actual account groups/pending and privately
owned selected KeyPackageRef are checked before SDK activation. The native transaction
tentatively stages the Welcome and checks the actual authenticated MLS welcomer
against current enrolled operators, actual group and selected native
KeyPackageRef. Only then does the native commit seam write/fsync the original
Welcome intent, before committing any KeyPackage consumption or group state.
Invalid or policy-mismatched input rolls back without spending the intent.
Policy refusal is deliberately distinct from native invalid-Welcome
deduplication, so it does not poison otherwise valid invitation bytes. A failed
intent write/fsync or later native commit remains UNKNOWN and never retries.
Exact native join evidence is then bound into a newly fsynced
header/independent-anchor mechanics and retained original-join record before
positively acknowledging the singleton matching native GroupJoined. Missing
durable write or partial/unknown effects retain original intent/pending evidence
when available and refuse. Wrong-group/operator/KeyPackage input is refused
inside the rollbackable native transaction before durable intent or native
commit. Unknown attempts never retry, reset state or manufacture enrollment;
positively rejected input permits the live loop to consider the next invitation.
SDK activation is bounded30seconds, finite wait1..86400seconds, SDK
shutdown5seconds. Notification loss before join holds; a dead relay forwarder
after durable enrollment does not negate completion. Shutdown timeout still
requires consumer UNKNOWN even if it follows a complete frame.
Individual invalid relay DTOs use the reviewed receiver forwarding behavior. The
anonymous ephemeral disk FIFO is opened through FD15, a private receiver-owned
mode0700 cache directory on a filesystem different from all durable journal,
anchor, intent and account locations; it has no
directory entry. This separation prevents an untrusted replay spool filling the
durable filesystems. It is not a disk reservation or an adversarial availability
guarantee. It is nonauthority storage and makes no restart promise; SDK lag or
I/O failure still holds.

Inbox replay remains `since: None`: NIP59 outer timestamps are intentionally
randomized and are not authenticated enrollment authority. The exact
root-enrolled native KeyPackageRef, expected group and actual MLS operator bind
this fresh attempt; historical invitations using other packages or already
consumed material are rejected before intent. A still-valid identical invitation
for the exact enrolled package/group/operator is the same authorized join, not a
fabricated historical enrollment. Only positively classified native Welcome
rejection or bounded oversized preintent rejection may continue intake. Backend/unknown errors stop, even if intent bytes
look empty.

The consumer sends32 fresh nonce bytes on the kernel-checked Unix stream. After
positive native enrollment, the response is the same bounded u32-BE framed
compact JSON with schema `heterodyne-owned-fresh-enrollment.v1`, nonce_hex,
startup_profile_sha256, actual derived enrollment, actual header_record,
header_sha256 and actual journal checkpoint. It is an enrollment correlation
response, not approval or deployment permission. Errors during the actual
Welcome exchange attempt a distinct `heterodyne-owned-fresh-enrollment-hold.v1`
frame retaining nonce/profile digest plus reconciliation/no-automatic-replay/
possible-native-UNKNOWN flags. Earlier startup/descriptor/account/nonce errors
remain EOF and exit2. A failed partial success write can be followed by HOLD,
and SDK shutdown failure can return exit2 after a success frame. Consumers must
accept only one complete checked success and the owned child normal exit0;
partial/extra bytes, EOF, HOLD or failed/unknown sender disposition remain
reconciliation-only UNKNOWN. No failure response asserts safe retry. Lost output
remains UNKNOWN; subsequent root-side recovery must inspect protected original
evidence and must not rerun this fresh-only entry. The separately owned consumer
must retain nonce, source child/UID/profile and original evidence; no JSON
authority importer exists.

Actual causal source tests use real native MLS, including a real signed NIP59
Welcome and forged-signature rejection followed by the genuine invitation. Other
MLS fixtures use the existing passthrough transport and synthetic protected
profiles. They prove derived enrollment, original retention before positive ack,
wrong group/operator/KeyPackage rollback followed by successful identical
original invitation, malformed input without spent intent, actual intent I/O
failure returning HOLD, inode-alias preflight, nonempty-anchor/invalid-policy
refusal, and actual read-only journal failure retaining native pending evidence.
They do not qualify a complete installed SDK+encrypted account+fresh
Welcome+protected publisher/consumer lifecycle, real-relay wait loop, malicious
traffic availability or actual host custody. Key bytes use existing workspace
Zeroizing on all returns; Nostr secret parsing avoids an unprotected hex-string
copy and SqlCipherKey already owns zeroizing key material. Existing shared
read_retained checks require regular single-link 0400 read-only
root/receiver-owned stable files, including key FDs.

The mutable anchor descriptor remains source-only durability mechanics. The
current approved independent guarded-consumer custody is not implemented by a
separate file or backup exclusion alone. The proposed descriptor-custody
amendment has separate review/human approval requirements; this source neither
implements nor claims that amendment. Root publisher, actual KeyPackage/account
provisioning, independent anchor custody, immutable source/runtime installation
and separate live enrollment/deployment approval remain prerequisites. Existing
unknown historical joins remain UNKNOWN.

R2 repair causal tests exercise the actual loop's attempt_welcome helper with an
oversized unauthenticated input followed by the real native invitation; actual
F_GETFL rejects read-only and append descriptors without effects, and device
comparison checks every durable position. These are composed helper tests,
not an installed SDK/Unix/SQLCipher end-to-end enrollment qualification. Native
backend failures during rollbackable foreign-Welcome processing still HOLD;
they are never relabeled as positively rejected input. The cache isolation is
not a space reservation, and out-of-space or durability faults still HOLD.
