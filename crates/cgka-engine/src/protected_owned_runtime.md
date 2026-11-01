# Fixed protected receiver process — source qualification

This is a Linux source-only process seam continuing the approved protected
receiver/recovery source. It does not install or enroll a receiver. The existing
protected journal, native MLS authentication, exact semantic binding, expiry and
one-use consume remain the authority path. No approval/candidate JSON importer or
caller-selected command is exposed. The process accepts no command-line arguments.

Build the actual binary with:

```
cargo build --locked -p cgka-engine --features protected-owner-runtime --bin heterodyne-protected-receiver
```

The fixed entry reopens an existing encrypted account, owns the actual Engine and
Nostr SDK adapter, executes the fixed Product producer, posts the exact generated
card if absent, receives actual SDK messages and emits an actual consumed
native receipt or a distinct nonauthorizing HOLD status. A previously retained ask must equal the current owned producer's
entire OriginalAsk before reuse. Native unknown/partial external effects remain
HOLD; there is no automatic replay or unconsume on transport failure.

## Private descriptor contract

This contract has no installed publisher yet. A separately enrolled protected
publisher must construct and retain these descriptors, source closures and account
provenance. Merely constructing the files below does not constitute enrollment.

| FD | Retained input |
|---|---|
| 3 | Root-owned, regular single-link read-only mode0400 closed startup profile |
| 4 | Exact32-byte Nostr account secret, regular read-only mode0400 |
| 5 | Exact32-byte encrypted DB key, regular read-only mode0400; SQLCipher passphrase is its lowercase hex encoding |
| 6–10 | Existing ordered journal, journal directory, storage lease, consumer anchor, anchor directory |
| 11–12 | Exact root-owned0400/O_RDONLY expiry.v1 profile matching enrollment.expiry_profile_sha256; disposable cache directory |
| 13 | Fixed Product `heterodyne-owned-card-profile.v1`, including exact target/profile/original/canonical/group/publication bindings |
| 14–15 | Complete retained Git archive and commit object |
| 16 | Protected existing account directory, mode0700 owned by receiver UID |
| 17 | Connected AF_UNIX/SOCK_STREAM consumer channel; kernel SO_PEERCRED UID must equal enrolled consumer UID |
| 18 | Exact original operation packet, regular single-link read-only mode0400, at most32768 bytes |

Startup profile schema is `heterodyne-protected-receiver-process.v2`, with closed
fields `receiver_uid`, `consumer_uid`, exact existing `enrollment`, `endpoints`,
`transport_group`, `python`, `product_source`, `purelib`, `producer_closure` (path,
SHA256 pairs) and `wait_seconds` (1..86400). The complete original profile bytes are
hashed separately from the serialized Enrollment. The account secret must match
Enrollment.account. The existing storage lease is acquired before opening SQLite.
The fixed account.sqlite3 basename must already exist, be regular/single-link,
mode0600 with the receiver owner, and is inspected using openat+O_NOFOLLOW.

The Product process uses the exact private `_entry` in Product source
35650c0ced0f9e1e3b1e5cefe36d5485fec74837. Its interpreter and supplied import files (including the required entry module)
are hash-read before/after invocation. Complete immutable import/stdlib custody
and interpreter installation are still enrollment prerequisites; these checks do
not prove the manifest is complete. Python runs isolated without environment
selectors, receives only fixed descriptors3/4/5 and original packet stdin, with a
30-second deadline, finite input/output, process-group cleanup and child reap.
No production account keys, journal, anchor or consumer descriptor survive exec.
This is a fixed trusted child lifecycle, not an adversarial process sandbox or a
qualified cgroup/reparenting fence.

## Consumed result channel

The independently owned consumer first sends exactly32 fresh random nonce bytes.
The receiver reads these with a finite5-second timeout. After successful durable
native consume it sends a4-byte unsigned big-endian JSON length, then compact JSON
(no newline), with at most256KiB. Private schema:

```
{
  "schema":"heterodyne-owned-consumed.v1",
  "nonce_hex":"<exact32-byte challenge, lowercase hex>",
  "startup_profile_sha256":"<exact original FD3 bytes>",
  "enrollment_sha256":"<serde JSON Enrollment>",
  "journal_profile_sha256":"<actual reopened protected journal profile>",
  "producer_closure_sha256":"<serde JSON enrolled ordered closure list>",
  "consumption_key":{
    "header_sha256":"<actual journal header digest>", "card_complete_sequence":0,
    "ask_id":"...", "original_operation_sha256":"<exact original packet>"
  },
  "original":{
    "ask_id":"...", "expected_group":[0],
    "operation":"<hex original packet>",
    "operation_canonical":"<hex canonical packet>",
    "original_request":"<hex original AskPost bytes>",
    "card_chunks":["<exact rendered card>"]
  },
  "receipt":{
    "sequence":0,"ask_id":"...","operation_sha256":"...",
    "packet_sha256":"...","request_sha256":"...","cards_sha256":"...",
    "policy_sha256":"...","operator":[0],"decision":"Approve",
    "authenticated_candidate":{
      "sequence":0,"received_at_unix_ms":0,"group":[0],
      "message_id":"...","source_epoch":0,"sender":[0],"application":{}
    }
  }
}
```

The example arrays/numbers/application object are illustrative, not an executable
fixture. Actual native GroupId/MemberId serialize as byte arrays. The receipt and
candidate come from the real Engine/semantic path; this wire has no deserializer
into authority. The consumer must own the opposite endpoint and receiver startup,
compare its fresh nonce, exact retained packet/canonical bytes/request/cards and
enrolled pins/current operator policy, and derive only the finite original scope.
An outer DeploymentPacket is not interchangeable with an inner native plan. Native
canonical operation envelopes must be derived/compared through the actual closed
approved mapping, not reconstructed from a boolean or receipt digest alone.

`consumption_key` is the exact native journal/anchor `Body::Consumed` key after
positive durable consume: generation/header digest, actual original CardComplete
record sequence, ask ID and original operation hash. Candidate `receipt.sequence`
is a distinct ingress sequence and cannot replace this key. Export refuses an
unconsumed, wrong-original or unbound journal. The consumer's one-use acceptance
must use the complete native key, never infer generation or card completion from
profile hashes or candidate sequence.

The response follows consume. A lost/partial output remains UNKNOWN; it does not
undo one-use state or authorize replay. A response is not a deployment permit on
its own. The consumer's durable acceptance/antirollback anchor and exact owner
composition remain integration prerequisites.

## Transport and limits

Deployment reopen subscriptions cover the enrolled group at every enrolled
endpoint, without a history floor. Fresh Welcome/inbox intake is a separate path. Every endpoint must report EOSE for the current
activation. The owner drains queued deliveries before inspecting approval. The
owner uses the actual SDK notification receiver directly: notification lag/error,
notification channel closure or shutdown ends the forwarder and prevents consume.
Individual invalid DTOs/transport events are skipped and counted before native
ingress. This excludes only definite pre-native DTO failures; valid-route opaque
ciphertext can still produce native UNKNOWN and HOLD as detailed below. Only
a definite non-latched pre-effect oversized ingress refusal is likewise skipped;
all uncertain/native-state failures remain HOLD.
This does not claim that EOSE proves human visibility or that unavailable relays
have no future messages. The existing card's transport-gap disclosures remain.

Activation/post are bounded30 seconds; per-request waiting is finite, SDK shutdown
is bounded5 seconds. A publication timeout may leave an incomplete durable intent,
which remains HOLD. Actual account/custody objects stay alive until forwarder
termination and shutdown attempt. The original unknown-operation policy, native
convergence/Add/Remove exclusions, historical preservation and100-unanswered intake
limit are unchanged.

## Actual qualification and remaining release HOLD

Focused tests exercise real native MLS approval and one-use consumption followed
by exact Unix framing, nonce and original-byte correlation; an injected lost write
does not unconsume. Actual kernel wrong-peer-UID and datagram tests refuse. Child
tests exercise real fixed-FD inheritance, no additional FD leak, deadline teardown
and reap, oversize stdout and nonzero exit. Product fixture tests use actual Product
fixture bytes, with explicitly synthetic HTTPS/profile provenance. Binary negative
checks refuse missing inherited descriptors and caller argv selectors with exit2,
empty stdout and static HOLD stderr. They are refusal qualification only.

The complete installed path (root publisher, protected account enrollment,
complete immutable producer/import closure, real relay replay and actual encrypted
account plus Product subprocess plus independently anchored native consumer in one
process composition) is NOT qualified by those tests. No deployment, live account,
queue or host change is made. New welcome/join provenance cannot be synthesized
for an existing unknown historical join. Release remains HOLD until genuine
custody, enrollment, end-to-end qualification and separate deployment approval.

Observed author checks: `cargo test --locked -p cgka-engine --features
protected-owner-runtime --lib owned_ -- --test-threads=2` passed16 tests in9.07s.
The initial full feature library suite passed224 tests with5 ignored in132.17s;
that binary predates two syntax-only Clippy fixes (a let-chain collapse and removal
of an immutable reborrow). The subsequent `cargo clippy --workspace --locked
--features cgka-engine/protected-owner-runtime -- -D warnings` passed36.42s.
A final-byte full suite is recorded separately in the packaging evidence.
`ripwire . --quality-delta` reports14 gating rows: adapter signer duplication with
simulator/bench examples, small canonical-base64/fd helper shape matches and
short-horizon churn from access changes. No clean quality verdict is claimed;
these structural findings are retained for review. The production signer uses
the existing proof-event/signature APIs rather than implementing cryptography.


Round-one repairs add actual production `exchange`/notification routing tests
using real native MLS, finite expiry and disk catalog plus fixture relay endpoint
ACK/EOSE. Signed malformed outsider replay and oversized native-boundary refusal
precede a genuine operator reply; no response appears before EOSE and the retained
card is not republished. Initial publication with missing EOSE/dead notification
forwarder refuses without consuming; lag/Shutdown end the forwarder. Idle waits
block on deliveries with a one-second expiry/readback timer rather than repeating
catalog/storage I/O every5ms. Startup owns inherited descriptor slots before Tokio
allocation; input readers share owner-checked positioned readback and post-open
SQLite dev/inode comparison. Producer teardown observes exit with waitid WNOWAIT,
kills its still-reserved process group, then reaps, never kills a reused PGID.
These are source qualification, not an installed account/producer/consumer run.

The supplied mutable anchor FD is source-only journal durability mechanics. It
does not qualify the approved independent guarded-consumer anchor service or its
authenticated protected-peer custody. A root-opened separate file or backup
exclusion alone does not establish independent consumer ownership. In particular,
a receiver-owned/co-restorable anchor cannot satisfy the approved design. Actual
consumer-owned anchor protocol/custody remains a deployment prerequisite.


## Round-two repair and explicit availability boundary

Deployment-only reopen activates group subscriptions without an inbox; fresh
Welcome enrollment remains a separate path. EOSE coverage counts only subscriptions
with actual endpoint attempts, so an empty inbox cannot block group-only replay.
A private anonymous O_TMPFILE FIFO in the already protected cache directory drains
SDK notifications independently of native journal/fsync latency. Event and EOSE
records retain FIFO order. This is ephemeral nonauthority storage, without a
restart/durability promise or lifetime cap. Per-record bounds remain; actual I/O
failure, SDK broadcast lag, shutdown or closed adapter ends intake and holds.
An actual causal test stalls adapter consumption while 5,200 signed records and
EOSE are spooled, then drains all records in order before coverage can complete.
This qualifies ordinary finite cooperative traffic, not arbitrary sustained floods.

Once the consumer peer and nonce are established, an exchange failure attempts the
same length-prefixed channel with schema `heterodyne-owned-receiver-hold.v1`, nonce
and startup/enrollment/journal digests, a closed reason code, and fixed flags
`reconciliation_required:true`, `automatic_replay_permitted:false`, and
`native_or_external_effects_may_be_unknown:true`. It carries no receipt, no success
key and no permission. Failure to deliver status does not release HOLD. Startup
failures before a validated peer/nonce retain fixed stderr/exit2 only. Consumers
must reject both unknown schemas and HOLD as authority. Consumer UID must be
nonzero and distinct from the receiver UID.

Cryptographic ambiguity is deliberately preserved. The transport peeler uses a
fresh ephemeral outer signing key per group event; an outer Nostr signer is not
the MLS operator. The group h-tag is public routing, not authenticated admission.
A real routed opaque cipher that cannot decrypt may be unrelated, future epoch,
or historical pending native work: the actual native state is PeelDeferred.
This source retains that UNKNOWN and quiet-HOLD, emits the nonauthorizing status,
and never reexecutes it. It does not terminal-reject arbitrary opaque ciphertext.
The causal test asserts retained native PeelDeferred, latched factory, exact HOLD,
no consumed receipt and no subsequent ingest/journal replay. Availability under
adversarial valid-route opaque input remains explicitly unqualified. Changing
that admission tradeoff needs a separate approved policy, not a speculative
classification that could discard contrary authorization history.

Python's supplied source paths now follow the isolated interpreter's standard
library instead of shadowing it. The complete immutable source/interpreter/import
closure remains an enrollment prerequisite, not established by hash manifests.
All current source tests remain synthetic protected-custody/relay fixtures; no
installed publisher, enrolled live account, fresh join, external consumer service,
anchor custody amendment or end-to-end deployment qualification is implied.

The consumed/HOLD schemas remain v1 because their fields and meanings are unchanged: `enrollment_sha256` always hashes the exact canonical retained Enrollment. Process-v2 binds Enrollment-v2, whose SHA includes distinct original fresh provenance and expiry-policy identities. Consumers must retain/check the exact enrolled version rather than reinterpret a v1 enrollment as v2.
