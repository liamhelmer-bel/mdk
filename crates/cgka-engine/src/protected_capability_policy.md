# Closed capability factory and rollbackable policy foundation

Source-only implementation within approved438y. This does not select a new
protected generation, publish any KeyPackage, enroll a group, enable a network
service or claim compatibility with the current MarmotApp group. Its required
SelfRemove Proposal10 remains unsupported. Closed v3 descriptor composition is
separate and is not implemented here.

`routing_only_v1()` and `bounded_app_receiver_v1()` return closed parameter-free
Template values. Components are pinned source constants, independent of future
mutable defaults. The bounded registry advertises only Optional receive F2D1;
no send/fanout extension or Proposal10 is advertised. Actual current wire
metadata is checked as sorted exact sets: extensions[6,F2D1], proposals[8] and
components[1,8001,8003,8004,8006,8009,800b,800c]. Routing has extensions[6],
proposals[8], components[1,8001,8003,8004,8009,800c]. MLS effective implicit
support1..6/1..8 differs from serialized metadata. This correct distinction is
retained as source evidence; future generation composition must bind the exact
closed recipe rather than silently interpreting old profiles differently.

The existing fixed native constructor now uses the explicit routing factory
with the same actual metadata; it never selects the bounded factory. Generic
engine defaults are unchanged. The private JoinConstraint additionally carries
a closed Template. Capture checks the authenticated staged MLS group after
native validation and before original intent writing/native commit. Bounded
checks reject every out-of-template dictionary entry, including optional entries
absent from the required component list, and unsupported required components,
proposals and extensions; reject every actual GroupContext extension container
except RequiredCapabilities and AppDataDictionary (a leaf capability does not
authorize extra live context state); require
Current profile; constrain QUIC policy to receive-required, receive|send allowed,
frame4096, replayTTL0, padding0; and reuse native V2 media validation with no V1
policy. Rejection is nonterminal rollback: unchanged Welcome can still pass the
native control, and no private package/group/intent/dedup state is spent. I/O or
commit uncertainty retains the existing UNKNOWN behavior.

Actual disposable tests verify both persisted private KP metadata sets, using
the production owned constructor for the routing metadata control;
native-valid optional-unknown dictionary and frame8192/fanout/replay/padding
refusals with identical-Welcome
native controls; actual OpenMLS unrequired outer ExternalSenders context extension refused
before intent with identical Welcome accepted by unchanged native/routing rules;
required Proposal10 and an unknown extension in deliberately
wider test engines; preexisting native unknown-component rejection; malformed
V2 and V1/V2 mixed creation refusal. Unsupported component/media creation
refusals do not claim that a valid Welcome reached the new policy seam. The
existing native join/intent failure tests remain part of the full suite.

Normative receive semantics are pinned by Hermes qualification commit
3ec7e4ed5b5df4893e2ac15d0bbb3dbc431548e1, docs/qualification/2026-10-30-receive-spec,
with official protocol commit156087dd09fa9a50d762249fdcb0450be7eef849.
The bounded fixture exercises actual MLS application ingest: authenticated
stream-start with approval-looking preview text is durably skipped, and a final
kind9 becomes an ordinary candidate with durable original/outcome ordering.
It does not run QUIC, open a media locator, validate a stream transcript hash,
consume a semantic approval, or qualify a complete production receive gate.
It changes no existing ingest classification. Existing unsupported state-update
and authority checks remain in effect.

Outstanding composition prerequisites are explicit generation/template/digest
binding, exact persisted metadata verification in production initialization and
fresh/resume ownership, complete functional qualification before advertisement,
actual intended group readback, and approved installed custody/deployment. This
foundation alone satisfies none of those runtime admission gates. Old profiles
and prepared/UNKNOWN records are never upgraded or adopted.

These causal tests require Linux and the protected-owner-runtime feature. The
recorded commands enable it explicitly; ordinary CI without that feature does
not exercise this private protected-owner test module. Future generation
composition must unify the separately fixed routing engine/constraint choices.
