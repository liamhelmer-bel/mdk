# agent-control

Local control-protocol DTOs and newline-delimited JSON framing for Marmot agent integrations.

This crate defines the `marmot.agent-control.v2` request/response/event types and the frame codec used over the
`wn-agent` Unix socket. Hermes and OpenClaw plugins are thin clients of this protocol.

The structured inbound-message, reply-context, and mutation-event schema is the
final intentionally breaking update shipped under the `v2` label while every
consumer is still released atomically from this repository. The `v2` schema is
stable after this change: any later breaking wire change must introduce a new
protocol label or explicit negotiation rather than silently changing `v2`.

`group_state_changed` includes an optional `event_id_hex`: the opaque durable
occurrence id shared by live events and storage replay. Older connectors omit
it. A change kind or timestamp alone is not a safe deduplication key.

Version 2 is intentionally incompatible with version 1. A successful `StreamBegin` returns a random 32-byte
`stream_capability` encoded as 64 lowercase hex characters. Every later append, status, progress, finalize, or cancel
request for that stream must present the capability. Treat it as an in-memory bearer secret: never persist or log it.

The envelope `id` is also the idempotency key for `StreamBegin`. Retrying the same begin request with the same `id`
returns the original stream id, start event, candidates, policy limit, and capability. Reusing that `id` with different
begin inputs is an error, and trying to begin another active stream with an occupied explicit stream id returns
`stream_id_in_use`; neither case replaces the existing session.

## Stream finalization

`stream_finish` accepts `stream_id_hex`, `stream_capability`, `final_text`, and an
optional `idempotency_key`. The shared publisher derives the hash and chunk count
from acknowledged text, status, and progress records. A text mismatch leaves the
stream active and returns the non-retryable `stream_finalize_mismatch` code; a
failed durable send retains the sealed transcript and returns the retryable
`stream_send_failed` code, so clients retry the same finish request. Successful
retries with the same inputs and key return the original message ids, including
after the connector restarts. Both paths return `stream_finalized`.

The existing `stream_finalize` remains supported and additionally validates the
client's `transcript_hash_hex` and `chunk_count`. New clients use `stream_finish`;
it is an additive v2 operation shipped with the companion connector. The
Hermes and OpenClaw plugins call `stream_finish` without a `stream_finalize`
fallback, so they are cohort-locked to the `wn-agent` release they ship with;
an older connector answers `control_error` and the plugins degrade to a plain
durable send without a live preview.

## What this crate does

- Owns `AgentControlEnvelope` and the typed control DTOs (bootstrap, send, subscribe, timeline history, invite policy, stream compose,
  allowlists, etc.).
- Provides newline-delimited JSON framing with a 1 MiB per-frame cap.
- Stays dependency-light: `serde` and Tokio IO only.

Invite-policy values serialize on the wire as `deny`, `allowlist`, `any_authenticated_direct`, and
`any_authenticated`. Deserialization also accepts the CLI spellings `any-authenticated-direct` and
`any-authenticated`.

## Group management and Welcome repair

`group_member_add` and `group_member_remove` take `account_id_hex`, `group_id_hex`,
and a `members` list of account references. Add also accepts `initial_admins`,
which must name invitees. `group_admin_add` and `group_admin_remove` take one
existing `member` reference. The connector uses the app runtime and MLS admin
policy; the local account must be a current group admin. Granting admin rights
to an existing member does not remove and re-invite that member.

Membership changes return `group_membership_updated` with
`pending_welcome_count`. A `null` or omitted count means the status read failed
after the MLS operation committed, so callers must query `group_welcome_status`
before deciding what to do. `group_welcome_status` lists durable undelivered
Welcomes for one group by message id, recipient id, and recording time. The same
entries appear as `maintenance_status.pending_welcomes`; they are Welcome
delivery obligations, separate from the MLS maintenance obligations. A zero
count only means this device has no undelivered Welcome record; it does not
prove that a recipient accepted an invite. Use the existing app runtime
`redeliver_welcome` repair path for a listed message id.

Errors expose a stable control `code` and, for app runtime failures, the
underlying `app_error_code`. Missing packages use `key_package_missing` with
`app_error_code: "missing_key_package"`; ask the recipient to publish a fresh
KeyPackage, then retry. Relay publication uses `relay_publish_failure` with
`app_error_code: "publish"`; query group state before retrying because the
MLS change may already be durable.

`invalid_key_package_capabilities` means the recipient must update its client
and republish a conforming package. `not_group_admin` means the local account
lacks MLS authority. `mls_commit_conflict` means the MLS epoch forked; refresh
group state before retrying. A repeated mutation can return an error once the
requested state already exists; inspect group state after a timeout.

`send_reaction` adds arbitrary non-blank, control-free reaction content of at
most 64 Unicode scalar values to a durable message. Repeating the same content
from the same account on the same target is idempotent and returns the existing
reaction id instead of publishing a duplicate.
`remove_reaction` takes the original target message id; callers do not need to
discover reaction event ids. An optional `emoji` retracts all of the calling
account's active reactions with that exact content. Omitting `emoji` retracts
all of the account's active reactions on the target in one durable delete event.

## Materialized timeline reads

`timeline_message_get` resolves one durable message id and `timeline_list` pages a
group's current materialized timeline with a stable `(recorded_at,
message_id_hex)` cursor. These are read-only views of current message state:
edits are reflected, reactions are aggregated, and deleted or invalidated
messages retain identity/attribution but never expose plaintext or attachment
metadata. Responses bound text, attachments, reactions, page size, and total
frame size.

Connectors use the same API both to attach a recent ID-bearing chat window to an
inbound turn and to expose an on-demand history tool. This is also the recovery
path after `resync_required`; clients should re-page the materialized timeline
rather than attempting to reconstruct history from the lossy event stream.

## What it does not do

- No engine, storage, account, or transport logic.
- No socket daemon or process lifecycle (see `agent-connector`).
- No QUIC preview composition (see `agent-stream-compose`).

## Run the tests

```sh
cargo test -p agent-control
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
