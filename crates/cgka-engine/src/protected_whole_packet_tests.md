# Correct Product native group context: disposable exchange qualification

This corrects the Product-domain error introduced in native114fe/PR207. The original native201 producer was not shown to have this domain bug. Actual `crates/agent-connector/src/account.rs:create_group_response` returns hex of the native runtime GroupId as GroupCreated.group_id_hex. CLI `groups.rs:created_group_output` likewise uses native GroupId; UniFFI `conversions/group.rs:From<CreatedGroup>` hex-encodes that value separately from AppGroupRecordFfi.nostr_group_id_hex. Product admind retains the returned group_id_hex. Product grammar accepts16–64bytes; generator's earlier32-byte assertion was an artificial test restriction.

The private GroupBinding still reads the owned authenticated MLS group's routing component and requires exact native and transport matches. Current routed groups without that component remain HOLD. Product profile/output/card context uses binding.native; transport subscriptions use binding.transport. Equal-length unit fixtures use native32/routing32 distinct values to show this is meaning, not length.

The ignored whole Product test checks pinned Productfaec83f17b92d3251e3118942c982661b085be59 HEAD and complete nonignored tracked/untracked cleanliness, then generates fresh finite packet bounds using the actual Product child and disposable Git proof. The explicit Product checkout may have genuinely Git-ignored test environments; those are not a complete installed import-closure attestation. Original/canonical packet, original AskPost and exact single OUTAGE card remain separately correlated. The Product child runs existing test bootstrap with synthetic HTTPS/render profile. This does NOT run InstalledProducer::produce or installed closure/startup/FD custody.

The positive current protocol fixture uses actual16-byte native MLS identity and authenticated32-byte routing, real Schnorr account proof, current FoundingGroupCreated, NIP59/445, disposable accounts/journal. Product receives native16. A second actual generated Product card receives routing32 and is refused by correlation without rewriting its rendered context.

The actual runtime exchange and notification forwarder perform activation, post, ingestion, EOSE replay coverage, native metadata preconsume recheck, durable consumption and frame emission. The driver ingests the published wire at an actual MLS operator, returns a real encrypted reaction as an SDK notification, and withholds EOSE to assert no early frame. It then provides exact subscription EOSE and checks the emitted consumed frame, operator/digest/nonce/original and full journal header/card/ask/operation key. Repeated consumption is refused; lost output does not reverse durable one-use. Relay ACK and notifications are disposable fixtures, not a real network relay or human approval.

Run explicitly with test dependencies:

```sh
HETERODYNE_QUALIFICATION_PRODUCT=/path/to/clean-pinned-product \
HETERODYNE_QUALIFICATION_PYTHON=/path/to/test-python \
CARGO_BUILD_JOBS=2 cargo test --locked -p cgka-engine \
 --features protected-owner-runtime \
 current_whole_product_packet_real_mls_approval_consumes_exact_checked_frame \
 --lib -- --ignored --nocapture
```

No expired generated packet is committed. No public authority importer/constructor, new design, pending198 custody mechanism, initializer203, protected root publisher/consumer enrollment or live deployment is implemented or qualified. Existing UNKNOWN/quiet-HOLD and prior source PoC limits remain. Actual source/test receipts belong to the H correction artifact; cached Cargo execution is not independent installed binary attestation.
