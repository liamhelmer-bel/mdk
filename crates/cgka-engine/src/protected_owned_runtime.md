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
card if absent, receives actual SDK messages and emits only an actual consumed
native receipt. A previously retained ask must equal the current owned producer's
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
| 11–12 | Existing protected expiry profile and disposable cache directory |
| 13 | Fixed Product `heterodyne-owned-card-profile.v1`, including exact target/profile/original/canonical/group/publication bindings |
| 14–15 | Complete retained Git archive and commit object |
| 16 | Protected existing account directory, mode0700 owned by receiver UID |
| 17 | Connected AF_UNIX/SOCK_STREAM consumer channel; kernel SO_PEERCRED UID must equal enrolled consumer UID |
| 18 | Exact original operation packet, regular single-link read-only mode0400, at most32768 bytes |

Startup profile schema is `heterodyne-protected-receiver-process.v1`, with closed
fields `receiver_uid`, `consumer_uid`, exact existing `enrollment`, `endpoints`,
`transport_group`, `python`, `product_source`, `purelib`, `producer_closure` (path,
SHA256 pairs) and `wait_seconds` (1..86400). The complete original profile bytes are
hashed separately from the serialized Enrollment. The account secret must match
Enrollment.account. The existing storage lease is acquired before opening SQLite.
The fixed account.sqlite3 basename must already exist, be regular/single-link,
mode0600 with the receiver owner, and is inspected using openat+O_NOFOLLOW.

The Product process uses the exact private `_entry` in Product source
35650c0ced0f9e1e3b1e5cefe36d5485fec74837. Its interpreter and supplied import files
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

The response follows consume. A lost/partial output remains UNKNOWN; it does not
undo one-use state or authorize replay. A response is not a deployment permit on
its own. The consumer's durable acceptance/antirollback anchor and exact owner
composition remain integration prerequisites.

## Transport and limits

Subscriptions cover both current account inbox and group at every enrolled
endpoint, without a history floor. Every endpoint must report EOSE for the current
activation. The owner drains queued deliveries before inspecting approval. The
owner uses the actual SDK notification receiver directly: notification lag/error,
conversion or adapter error, or shutdown ends the forwarder and prevents consume.
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
