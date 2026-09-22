# Detectable inbound subscription liveness

Design for Bead `btq-harness-fa7858117ffd9645d0c01d5f`, 2026-09-21.
Reviewed source: `28db7b3bffe01eed7c8c61f0984d253a6a755213`.
Status: proposed, not implemented or authorized for implementation by this Bead.

## Decision and evidence

Negotiate periodic **server-to-client progress frames on the subscribed socket**.
Do not use a separate control ping as proof of subscription health. Keep transport,
relay ingestion, durable admission, and handler progress as separate observations.
No user-message traffic is required to keep a healthy idle subscription alive.

The existing producer in [inbound.rs](../crates/agent-connector/src/inbound.rs)
ACKs before initial catch-up completes, drains runtime/debug/catch-up broadcasts,
and replays a bounded storage window on runtime lag. The writer in
[connection.rs](../crates/agent-connector/src/connection.rs) already bounds each
frame write/flush to 15 seconds. Initial catch-up is concurrent, but live event
hydration and storage replay execute synchronously inside the drain loop.

The Python [client](../integrations/hermes/marmot/agent_control.py) explicitly uses
`timeout=None` after ACK. Its generator yields to the adapter, which awaits
`_handle_control_event` inline before reading again. Per-group turns are separately
queued, but this does not remove every inline handler from the wire-reading path.
The Rust [terminal harness](../integrations/terminal-harness/src/control.rs) has a
reader task with a bounded 256-event channel; channel backpressure can stop reads.
Neither consumer should diagnose producer failure solely from handler-log silence.

These observations establish a design gap. They do not identify the cause of the
historical outage. Earlier incident evidence also supports a hung group turn, and
must not be rewritten as proof of a producer stall.

## Compatibility and negotiation

Keep `marmot.agent-control.v2` and the existing request name. Add an optional
`liveness` object to `subscribe_inbound`, for example `{"version":1}`. Absence
preserves today's stream exactly. A new server rejects malformed/unsupported
explicit liveness versions with a stable capability error before streaming.

For an opted-in request, the ACK carries an optional accepted `liveness` object:
`version`, `heartbeat_interval_ms`, and `silence_deadline_ms`. Proposed initial
values are 10,000 and 45,000 ms. They are design defaults, not measured service
SLOs; validate them under the workload matrix before release. Clients validate
finite, bounded values and require deadline >= three heartbeat intervals plus
scheduling allowance. Negotiation is scoped to this connection and request ID.

Only after an explicit accepted ACK may the server send `subscription_progress`
frames, and only then may the client arm a quiet-stream deadline. New consumers
must parse this event before opting in. Existing Rust enum consumers must never
receive new event variants through an unnegotiated subscription.

| Client / server | Result |
| --- | --- |
| Old / old | Existing ACK and event stream. |
| Old / new | No opt-in: no new frames or changed idle behavior. |
| New / old | Old server may ignore the optional field and return a plain ACK; client stays in legacy mode, marks liveness unsupported, and does not time out healthy silence. |
| New / new | Accepted version and validated bounds enable progress frames and deadline monitoring. |

Test actual Serde and Python decoders, including old fixtures, rather than assuming
unknown-field behavior guarantees compatibility. Never infer negotiation from a
successful connection, ACK alone, binary version string, or a separate ping. If an
old server explicitly rejects the optional field, allow at most one legacy retry;
never downgrade authentication, framing, or other errors into a capability fallback.

## Progress semantics and state machine

A progress frame uses the existing envelope/request ID and contains only aggregate
fields: monotonic connection-local `sequence`, `catch_up_state`
(`pending|complete|failed`), frames successfully flushed, replay state, and coarse
ages for independently observed runtime activity. An unknown relay-health value
must remain unknown. No account/group/message identifiers, URLs, payloads, or key
material belong in these diagnostic fields. Connection sequence is not a durable
replay cursor and must not be persisted or interpreted across reconnects.

States are `connecting -> negotiated|legacy -> streaming -> suspect -> closed`.
EOF/error closes immediately. For negotiated streaming, a complete valid frame
with the expected request ID advances the wire receipt timestamp; only an advancing
progress sequence updates progress-frame state. Duplicate progress sequences do
not renew the lease. Partial bytes, malformed frames, handler completion and
control pings cannot renew it. Use a local monotonic clock, not remote wall time.
A deadline expires at or after 45 seconds since the last qualifying receipt.

Generate progress in the same subscription coordinator that advances event
projection. Use a single writer and serialized frames; never interleave heartbeat
bytes with an event. Check the due timer between bounded event/replay batches and
prevent a permanently ready event source from starving it. Coalesce delayed ticks;
do not emit a burst to repay missed ticks. Write success proves kernel acceptance,
not client receipt or durable handling. Only the client can report receipt.

A background timer independent of a wedged projector must not keep emitting a
misleading healthy lease. If a separate writer task is needed, progress renewal
requires a fresh coordinator progress token; buffered stale tokens cannot renew it.
If synchronous hydration stalls, progress stops and the receiver detects silence.
Tokio timers cannot interrupt a blocking storage call or a starved executor.

Moving hydration to a worker is a separate implementation choice: use bounded
concurrency and report outstanding operation age. Timing out `spawn_blocking`
does not cancel its work. Do not spawn a replacement on each heartbeat expiry or
let reconnects accumulate blocked workers. Shared executor failure requires host
supervision; this protocol cannot guarantee its own server-side cleanup then.

## Consumer backpressure and dispatch

Separate the socket pump from inline handlers. The pump validates framing and
records receipt before admission; it consumes progress frames itself, never
passes them to agent turns, and preserves application-event order in a bounded
queue or durable spool. Apply both count and byte limits. Record wire receipt,
last durable admission, queue depth/oldest age, and handler start/completion
independently. A healthy pump with a stuck handler is consumer congestion.

A full queue cannot simply discard business events so the reader can keep finding
heartbeats. Prefer durable admission with a bounded pending buffer. When capacity
is exhausted, classify `consumer_backpressure`, retain already admitted work, and
stop/resume reading according to a bounded recovery policy. During a locally
blocked read, producer liveness is **unknown**, not failed. Do not restart a healthy
producer or reconnect repeatedly to a consumer that cannot drain its own queue.
The Rust harness's 256-event channel needs the same treatment as Python handlers.

For genuine negotiated silence with available consumer capacity, close the socket
and reconnect with jittered exponential backoff and a cap. Reset backoff only after
a sustained healthy interval (proposed 60 seconds), not merely after ACK: repeated
ACK-then-silence must not repeatedly receive the minimum delay. Host suspend/event
loop starvation invalidates the timing observation; report a local scheduling gap,
use one bounded revalidation/reconnect, and avoid mass simultaneous reconnects.
Never reconnect legacy subscriptions merely because no user message arrived.

## Recovery is a separate correctness contract

Current reconnect is not a proven full replay mechanism. `DeliveredInboundCursor`
is connection-local, bounded, and records IDs before successful delivery is
acknowledged by a consumer. Initial catch-up completion is consumed internally;
it does not certify that every already-processed durable row was re-emitted.
The newest-window replay on broadcast lag cannot by itself prove that an arbitrary
reconnect gap is covered. A broadcast drop count is not a durable history boundary.

Before enabling automatic timeout recovery as a lossless feature, provide and test
an explicit resumable reconciliation contract. Recommended design:

1. Capture a durable, ordered high-water mark for the authenticated subscription
   scope, then subscribe/buffer live changes while replaying through that mark.
2. Resume from a consumer cursor advanced only after durable admission. The cursor
   is opaque and scope-bound on the wire, never diagnostic log content. Reject
   scope changes or invalid cursors; treat expired history as an explicit gap.
3. Replay all relevant facts, including already-processed rows, edits, deletions,
   reactions and group-state changes, using stable event identity/revision keys.
   A current timeline snapshot is not automatically a journal of removed facts.
4. Deduplicate the replay/live overlap durably; do not claim exactly-once side
   effects without transactional admission and execution/idempotency boundaries.
5. If the retention horizon prevents replay, emit `resync_required` with an explicit
   gap category and enter degraded reconciliation. Do not announce caught-up or
   advance the cursor past an unproven gap. Define full snapshot/tombstone recovery
   separately for the supported event classes.

This may require a durable event journal and schema work; this design does not
assert the current storage API already supplies those guarantees. The first
heartbeat-only delivery may expose diagnostics without promising lossless timeout
recovery. Gate automatic recovery claims on the reconciliation tests below.

## Privacy-safe lifecycle evidence and the logging sink

Add `target="agent_connector"`, `method="stream_inbound_events"` lifecycle records:
open, negotiated/legacy, catch-up result, lag count, replay count/result, write
failure, and close with a fixed reason category. Emit one terminal record on every
exit path, including task cancellation where feasible; process death requires an
external absence-of-progress signal. Keep active/closed counters balanced. Emit
bounded periodic aggregates rather than every heartbeat and rate-limit failures.

Mirror client categories: wire receipt age, progress age, durable admission age,
queue depth/bytes/oldest age, dispatch age, local scheduling gap, reconnect attempt,
and negotiated/legacy mode. Use fixed enums, counts and durations; no sensitive
identifiers, hashed identities, free-form errors, endpoints or sensitive paths.
A separate control ping establishes only control-service responsiveness. A heartbeat
establishes subscription coordinator/transport progress, not relay freshness,
storage integrity, successful dispatch, or completion of a user turn.

Read-only host evidence collected during this work:

- The installed binary SHA-256 was
  `da2b1ae1c488fde43387d5948e7a0bebe3501fbb4b0367c225ed11ac18e72505`.
  Its source provenance was not established from that hash alone.
- The on-disk service unit invokes the installed daemon without an explicit output
  override. Effective service configuration could not be queried: the sandbox's
  user-bus connection failed. Process enumeration did not expose a wn-agent PID;
  this is not proof that the host service is stopped.
- The readable user journal returned 133 records in the preceding 24-hour query,
  with zero `subscription` or `agent_connector` keyword matches. This establishes
  absence in that sample, not successful tracing delivery or absence of failures.
- No `tracing_subscriber`, `set_global_default` or `set_default(` occurrence was
  found in the reviewed connector/app/account source trees. Other dependencies,
  consent-based telemetry setup and installed source may differ; do not infer an
  effective global subscriber solely from this search.

**Installed lifecycle tracing is not verified.** Adding tracing calls alone is
insufficient. Manager-side acceptance must record effective output routing and
binary provenance, then observe a harmless isolated subscription open/close marker
at the actual sink. First prove subscriber/filter behavior in a subprocess using
an isolated home and captured stderr; never open the live shared home for this
probe. A manager-authorized live verification then checks the matching deployed
cohort. If markers do not reach the sink, add a process-owned local tracing
subscriber with tested filters, privacy-safe targets and bounded retention; do not
silently change telemetry consent or enable broad payload logging.

## Required implementation verification

These are future acceptance tests, not claims that a heartbeat implementation was
tested in this research Bead. Use paused clocks and deterministic fault injection
where possible, then a staged-home end-to-end run with the actual client/daemon.

| Scenario | Required observation |
| --- | --- |
| Healthy idle for many deadlines | Negotiated progress advances; zero reconnects without user messages. |
| ACK then silence | One bounded expiry, socket closed, jitter/backoff increases across repetitions. |
| Legacy mixed versions | Plain ACK never arms silence timeout; old clients never see new events. |
| Malformed/version/sequence mismatch | Reject invalid negotiation/frame; duplicate progress cannot renew lease. |
| Producer closure/write timeout | One terminal reason; EOF reaches consumer; no orphan reader/writer tasks. |
| Slow inline handler | Pump receipt continues until bounded capacity; handler stall is separately visible. |
| Full spool/channel | Consumer congestion, no dropped admitted events or reconnect storm; bounded memory. |
| Synchronous hydration blocked | No independent false heartbeat; deadline or local-starvation diagnosis; bounded worker count. |
| Continuous event/replay load | Progress is not starved; complete frame ordering and frame cap preserved. |
| Runtime lag and replay failure | Correct recovery/gap category; no silently successful partial replay. |
| Reconnect after durable processing before delivery | Already-processed row recovered, not only new relay notifications. |
| Crash after admission before cursor update | Replay deduplicates durable admission; no duplicate side effects claimed without proof. |
| Replay/live race; mutation/deletion | Stable identity/revision handling and ordered reconciliation preserve facts. |
| Gap beyond retention; scope change | Explicit degraded/gap result; no false caught-up state or cross-scope replay. |
| Partial inbound frame interrupted by timer | Persistent bounded decoder retains bytes; EOF/oversize behavior deterministic. |
| Logging filter/sink | Open/close/lag markers reach captured and installed sinks; prohibited data absent. |
| Suspend/resume and many subscribers | Bounded revalidation, no synchronized reconnect burst, no unbounded task growth. |

## Implementation boundaries and rollout

No subscriber-to-server heartbeat or receipt ACK is proposed for the first phase.
Nevertheless, make cancellation-safe framing a prerequisite to enabling the new
liveness exchange, rather than leaving a trap for later client frames or cursor
ACKs. Replace the current temporary-buffer `read_envelope` select branch with persistent
bounded framing or a dedicated non-cancelled reader task. `read_until` retains
partial bytes in its buffer, but that buffer currently lives inside the cancelled
future and is dropped. Preserve the 1 MiB frame cap and test adversarial partial
frames, cancellation, EOF and multiple frames before enabling duplex traffic.

Sequence separately authorized work as: cancellation-safe framing;
negotiated producer progress and sink; consumer pump/observations/backpressure;
reconciliation/cursor correctness; then timeout recovery and deployment acceptance.
Ship producer capability before consumer opt-in. Roll back by disabling opt-in;
keep legacy idle behavior available. Coordinate client/daemon versions and any
shared-home migration through the manager, with offline candidate validation and
rollback evidence. Deployment is handled by the manager. No service restart,
shared-home access, schema change or protocol implementation occurred here.

## Research validation performed

- `cargo test -p agent-control --locked`: 25 passed, zero failures.
- `cargo test -p agent-connector connector_socket_subscribe_terminates_when_client_disconnects --locked`:
  the selected existing regression passed (one test); remaining tests were filtered.
- `just --tempdir /tmp fast-ci`: passed, including workspace formatting/check/clippy
  and its policy gates. `/tmp` avoids the sandbox's read-only default runtime tempdir.
- Document links and whitespace checks passed. The docs scan returned only two
  existing matches in unrelated architecture documents.

The disconnect regression exercises an isolated local socket and temporary home.
No new protocol implementation exists to dogfood. Full connector/workspace suites,
new heartbeat acceptance tests, and deployed sink verification were not performed;
they are not implied by these results. Research logs and hashes are retained in
the Bead's harness evidence directory, outside the checkout.

### Installed binary probe and journal transport follow-up

A follow-up inspection of the retained 133-record journal sample found 117 records
with `_TRANSPORT=stdout` and `SYSLOG_IDENTIFIER=wn-agent`, and 16 systemd journal
records. Thus the sample positively establishes daemon stdout/stderr transport to
journald. It does **not** establish that the subscription tracing target reaches it.

The installed binary with the hash above was also run as a separate subprocess
with a new empty temporary home, its own Unix socket, a loopback-only relay setting,
and `RUST_LOG=agent_connector=trace`. The probe received a valid subscription ACK,
sent a second subscription request (which exercises a warning path in the reviewed
source), disconnected, and terminated only its own subprocess. Captured stdout
and stderr were both empty. The binary hash was unchanged. No live daemon or
shared account home was touched.

This is negative logging evidence, not a successful lifecycle-sink test. Without
installed source provenance it cannot prove which internal branch executed, and
absence of a marker cannot prove the absence of every tracing subscriber. It does
show that this exercised subscription path produced no captured log under the
requested filter. Keep verified stdout transport and unverified subscription
tracing as separate results. The implementation acceptance gate must supply an
explicit positive open/close marker observed at the configured sink; merely
setting `RUST_LOG` is not a demonstrated repair.
