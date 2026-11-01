use super::*;
use crate::Engine;
use crate::protected_receiver::tests::{build_client, key};
use cgka_traits::app_components::{
    AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, default_group_components,
    encode_nostr_routing_v1,
};
use cgka_traits::transport::TransportEnvelope;
use cgka_traits::{TransportAccountActivation, TransportAdapterError, engine::CreateGroupRequest};
use std::sync::{Arc, Mutex};
use storage_sqlite::SqliteAccountStorage;
use transport_nostr_adapter::{NostrPublishOutcome, NostrRelayClient, NostrSubscription};
use transport_nostr_peeler::{NostrMlsPeeler, NostrTransportEvent};

#[derive(Default)]
pub(super) struct Relay {
    pub(super) wires: Mutex<Vec<TransportMessage>>,
    pub(super) subscriptions: Mutex<Vec<NostrSubscription>>,
    fail_at: Mutex<Option<usize>>,
}
#[async_trait::async_trait]
impl NostrRelayClient for Relay {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }
    async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
        Ok(())
    }
    async fn unsubscribe_account(&self, _: &MemberId) -> Result<(), TransportAdapterError> {
        Ok(())
    }
    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        _: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        // Actual adapter verifies signed Nostr wire conversion; relay ack is an injected fixture.
        let wire = event.to_transport_message().unwrap();
        let mut wires = self.wires.lock().unwrap();
        wires.push(wire);
        if *self.fail_at.lock().unwrap() == Some(wires.len()) {
            return Err(TransportAdapterError::Publish(
                "injected lost publish return".into(),
            ));
        }
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}
pub(super) fn client(seed: &[u8]) -> Engine<SqliteAccountStorage> {
    let (engine, _) = build_client(seed);
    // Reuse actual Engine identity/signature fixture, but real kind-445/NIP59 peeler.
    let storage = engine.storage.clone();
    restart_client(seed, storage)
}
fn restart_client(seed: &[u8], storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    let mut supported = default_group_components();
    supported.insert(NOSTR_ROUTING_COMPONENT_ID);
    crate::EngineBuilder::new(storage)
        .supported_app_components(supported)
        .legacy_compatibility_profile()
        .identity(key(seed).verifying_key().to_bytes().to_vec())
        .account_identity_proof_signer(Arc::new(
            crate::distributed_convergence::tests::TestProofSigner(key(seed)),
        ))
        .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(
            nostr::Keys::parse(&hex::encode(key(seed).to_bytes())).unwrap(),
        )))
        .build()
        .unwrap()
}
pub(super) async fn fixture() -> (
    SemanticFactory<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    tempfile::NamedTempFile,
    Arc<Relay>,
) {
    let mut operator = client(b"semantic-operator");
    let mut controller = client(b"semantic-controller");
    let mut kp = controller.fresh_key_package().await.unwrap();
    kp.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: cgka_traits::types::MessageId::new(vec![4; 32]),
    });
    let route = NostrRoutingV1::new([7; 32], vec!["wss://semantic.invalid".into()]).unwrap();
    let (group, created) = operator
        .create_group(CreateGroupRequest {
            name: "semantic".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&route).unwrap(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("group")
    };
    operator.confirm_published(pending).await.unwrap();
    let welcome=welcomes.into_iter().find(|w|matches!(&w.envelope,TransportEnvelope::Welcome{recipient} if recipient==&controller.self_id())).unwrap();
    controller.join_welcome(welcome).await.unwrap();
    operator.drain_events();
    controller.drain_events();
    let file = tempfile::NamedTempFile::new().unwrap();
    let receiver = ProtectedReceiver::new(
        controller,
        group,
        vec![operator.self_id()],
        file.reopen().unwrap(),
    )
    .unwrap();
    let relay = Arc::new(Relay::default());
    let transport = NostrTransportAdapter::new(relay.clone());
    transport
        .activate_account(TransportAccountActivation {
            account_id: receiver.engine.self_id(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    (
        SemanticFactory::new(
            receiver,
            transport,
            vec![TransportEndpoint::from("wss://semantic.invalid")],
        )
        .unwrap(),
        operator,
        file,
        relay,
    )
}
pub(super) fn original(id: &str, group: &cgka_traits::types::GroupId) -> OriginalAsk {
    OriginalAsk {
        ask_id: id.into(),
        expected_group: group.clone(),
        operation: b"exact source-only operation".to_vec(),
        operation_canonical: b"canonical source-only operation".to_vec(),
        original_request: b"exact original admind input bytes".to_vec(),
        card_chunks: vec![
            format!("{id}: existing producer exact card part one"),
            format!("{id}: existing producer exact card part two"),
        ],
    }
}
pub(super) async fn reaction(
    operator: &mut Engine<SqliteAccountStorage>,
    factory: &SemanticFactory<SqliteAccountStorage>,
    target: &str,
    emoji: &str,
) -> TransportMessage {
    app_wire(
        operator,
        factory,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![vec!["e".into(), target.into()]],
        emoji,
    )
    .await
}
#[tokio::test]
async fn real_owned_send_publish_multipart_mls_decision_and_one_use() {
    let (mut f, mut operator, file, relay) = fixture().await;
    f.post(original("ask3", &f.receiver.group)).await.unwrap();
    let wires = relay.wires.lock().unwrap().clone();
    assert_eq!(wires.len(), 2);
    for w in wires {
        operator.ingest(w).await.unwrap();
    }
    operator.drain_events();
    let target = f.asks["ask3"].app_ids[1].clone();
    let wire = reaction(&mut operator, &f, &target, "👍🏽").await;
    assert_eq!(f.ingest(wire).await.unwrap(), Some("ask3".into()));
    let hash = digest(b"exact source-only operation");
    assert!(f.consume("ask3", &"00".repeat(32)).is_err());
    let receipt = f.consume("ask3", &hash).unwrap();
    assert_eq!(receipt.decision, Decision::Approve);
    assert_eq!(receipt.operation_sha256, hash);
    assert!(f.consume("ask3", &hash).is_err());
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(file.path())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        lines
            .iter()
            .filter(|l| l["schema"] == "semantic-published.v1")
            .count(),
        2
    );
    let decision = lines
        .iter()
        .position(|l| l["schema"] == "semantic-decision.v1")
        .unwrap();
    let raw = lines
        .iter()
        .position(|l| l["schema"] == "receiver-wire.v1")
        .unwrap();
    assert!(raw < decision);
    assert_eq!(lines.last().unwrap()["schema"], "semantic-consumed.v1");
}
#[tokio::test]
async fn uncertain_second_publish_never_completes_card_or_replays() {
    let (mut f, _, file, relay) = fixture().await;
    *relay.fail_at.lock().unwrap() = Some(2);
    assert!(f.post(original("ask3", &f.receiver.group)).await.is_err());
    assert!(f.held);
    assert!(f.asks.is_empty());
    assert_eq!(
        f.post(original("ask2", &f.receiver.group))
            .await
            .unwrap_err(),
        ReceiverHold::Latched
    );
    assert_eq!(relay.wires.lock().unwrap().len(), 2);
    assert!(
        !std::fs::read_to_string(file.path())
            .unwrap()
            .contains("semantic-card-complete.v1")
    );
}
#[tokio::test]
async fn policy_change_and_exact_target_and_denial_refuse_consumption() {
    let (mut f, mut operator, _, _) = fixture().await;
    f.post(original("ask3", &f.receiver.group)).await.unwrap();
    let unknown = reaction(&mut operator, &f, &"00".repeat(32), "👍").await;
    assert_eq!(f.ingest(unknown).await.unwrap(), None);
    let target = f.asks["ask3"].app_ids[0].clone();
    let deny = reaction(&mut operator, &f, &target, "👎").await;
    assert!(f.ingest(deny).await.unwrap().is_some());
    assert!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .is_err()
    );
    let (mut f, mut operator, _, _) = fixture().await;
    f.post(original("ask2", &f.receiver.group)).await.unwrap();
    let target = f.asks["ask2"].app_ids[0].clone();
    let approve = reaction(&mut operator, &f, &target, "👍").await;
    f.receiver.operators.push(MemberId::new(vec![9; 32]));
    assert_eq!(
        f.ingest(approve).await.unwrap_err(),
        ReceiverHold::ChangedState
    );
    assert!(f.held);
}
#[test]
fn reaction_vocabulary_is_existing_finite_admind_subset() {
    for s in ["👍", "👍🏻", "👍🏿", "✅"] {
        assert_eq!(emoji_action(s), Some(Decision::Approve));
    }
    for s in ["👎", "👎🏽", "❌"] {
        assert_eq!(emoji_action(s), Some(Decision::Deny));
    }
    for s in ["👍👍", "👍🏻🏽", "yes", " 👍", "no idea", "❤️", "♥"] {
        assert_eq!(emoji_action(s), None);
    }
}

#[tokio::test]
async fn product_owned_fixture_preserves_original_digest_and_refuses_wrong_group() {
    // Cross-language source fixture only; no public plaintext receipt import.
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/protected-semantic/whole-packet-v1.json"
    ))
    .unwrap();
    let p = &v["prepared"];
    let raw = hex::decode(p["operation_original"].as_str().unwrap()).unwrap();
    let canonical = hex::decode(p["operation_canonical"].as_str().unwrap()).unwrap();
    assert_ne!(raw, canonical);
    assert_eq!(
        digest(&raw),
        p["operation_original_sha256"].as_str().unwrap()
    );
    assert_eq!(digest(&canonical), p["packet_sha256"].as_str().unwrap());
    assert_ne!(digest(&raw), digest(&canonical));
    let request = hex::decode(p["request_original"].as_str().unwrap()).unwrap();
    let request_json: serde_json::Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(request_json["kind"], "question");
    assert_eq!(request_json["form"], "yes-no");
    assert_eq!(request_json["recommended"], "yes");
    let (mut f, _, _, relay) = fixture().await;
    let original = OriginalAsk {
        ask_id: p["ask_id"].as_str().unwrap().into(),
        expected_group: cgka_traits::types::GroupId::new(
            hex::decode(p["group_hex"].as_str().unwrap()).unwrap(),
        ),
        operation: raw,
        operation_canonical: canonical,
        original_request: request,
        card_chunks: vec![p["card"].as_str().unwrap().into()],
    };
    assert_ne!(original.expected_group, f.receiver.group);
    assert_eq!(
        f.post(original).await.unwrap_err(),
        ReceiverHold::Configuration
    );
    assert!(!f.held);
    assert!(relay.wires.lock().unwrap().is_empty());
}

async fn app_wire(
    operator: &mut Engine<SqliteAccountStorage>,
    f: &SemanticFactory<SqliteAccountStorage>,
    kind: u64,
    tags: Vec<Vec<String>>,
    text: &str,
) -> TransportMessage {
    let app = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1,
        kind,
        tags,
        text,
    );
    let SendResult::ApplicationMessage { msg, .. } = operator
        .send(SendIntent::AppMessage {
            group_id: f.receiver.group.clone(),
            payload: app.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("app")
    };
    msg
}
pub(super) async fn approve(
    f: &mut SemanticFactory<SqliteAccountStorage>,
    operator: &mut Engine<SqliteAccountStorage>,
    id: &str,
) {
    f.post(original(id, &f.receiver.group)).await.unwrap();
    let target = f.asks[id].app_ids[0].clone();
    let wire = reaction(operator, f, &target, "👍").await;
    assert_eq!(f.ingest(wire).await.unwrap(), Some(id.into()));
}
#[tokio::test]
async fn contrary_chat_and_reaction_removal_block_only_relevant_approval() {
    let (mut f, mut operator, _, _) = fixture().await;
    approve(&mut f, &mut operator, "ask3").await;
    let wire = app_wire(
        &mut operator,
        &f,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "!answer ask3 no",
    )
    .await;
    assert_eq!(f.ingest(wire).await.unwrap(), None);
    assert!(!f.held);
    assert_eq!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .unwrap_err(),
        ReceiverHold::ChangedState
    );
    approve(&mut f, &mut operator, "ask2").await;
    let receipt = &f.asks["ask2"]
        .receipt
        .as_ref()
        .unwrap()
        .authenticated_candidate
        .application
        .id;
    let wire = app_wire(
        &mut operator,
        &f,
        MARMOT_APP_EVENT_KIND_DELETE,
        vec![vec!["e".into(), receipt.clone()]],
        "",
    )
    .await;
    assert_eq!(f.ingest(wire).await.unwrap(), None);
    assert!(!f.held);
    assert_eq!(
        f.consume("ask2", &digest(b"exact source-only operation"))
            .unwrap_err(),
        ReceiverHold::ChangedState
    );
    // A third unrelated exact ask still posts and produces its own receipt.
    approve(&mut f, &mut operator, "ask4").await;
    f.consume("ask4", &digest(b"exact source-only operation"))
        .unwrap();
}
#[tokio::test]
async fn unrelated_hinted_multitarget_reaction_does_not_latch_and_hex_case_matches() {
    let (mut f, mut operator, _, _) = fixture().await;
    f.post(original("ask3", &f.receiver.group)).await.unwrap();
    let unrelated = app_wire(
        &mut operator,
        &f,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![
            vec!["e".into(), "00".repeat(32), "wss://hint.invalid".into()],
            vec!["e".into(), "11".repeat(32)],
        ],
        "👍",
    )
    .await;
    assert_eq!(f.ingest(unrelated).await.unwrap(), None);
    assert!(!f.held);
    let target = f.asks["ask3"].app_ids[0].to_ascii_uppercase();
    let actual = app_wire(
        &mut operator,
        &f,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![vec!["e".into(), target, "wss://hint.invalid".into()]],
        "👍",
    )
    .await;
    assert_eq!(f.ingest(actual).await.unwrap(), Some("ask3".into()));
    let contrary = reaction(&mut operator, &f, &f.asks["ask3"].app_ids[0], "👎").await;
    assert_eq!(f.ingest(contrary).await.unwrap(), None);
    assert!(!f.held);
    assert_eq!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .unwrap_err(),
        ReceiverHold::ChangedState
    );
}
#[tokio::test]
async fn policy_changed_after_retained_approval_refuses_consumption() {
    let (mut f, mut operator, _, _) = fixture().await;
    approve(&mut f, &mut operator, "ask3").await;
    f.receiver.operators.push(MemberId::new(vec![9; 32]));
    assert_eq!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .unwrap_err(),
        ReceiverHold::ChangedState
    );
}
#[tokio::test]
async fn completed_history_crosses_former_32mib_cap_and_new_ask_still_posts() {
    let (mut f, mut operator, file, _) = fixture().await;
    let alphabet = b"23456789abcdefghjkmnpqrstuvwxyz";
    for i in 0..80 {
        let id = format!(
            "ab{}{}",
            alphabet[i / alphabet.len()] as char,
            alphabet[i % alphabet.len()] as char
        );
        let mut input = original(&id, &f.receiver.group);
        input.operation = vec![0x5a; 64 * 1024];
        input.operation_canonical = vec![0x5b; 64 * 1024];
        input.original_request = vec![0x5c; 64 * 1024];
        input.card_chunks = vec![format!("{id} {}", "z".repeat(23000))];
        f.post(input).await.unwrap();
        let target = f.asks[&id].app_ids[0].clone();
        let deny = reaction(&mut operator, &f, &target, "👎").await;
        assert_eq!(f.ingest(deny).await.unwrap(), Some(id));
    }
    assert!(file.as_file().metadata().unwrap().len() > 32 * 1024 * 1024);
    assert_eq!(f.asks.values().filter(|a| a.receipt.is_none()).count(), 0);
    f.post(original("ask3", &f.receiver.group)).await.unwrap();
    assert!(!f.held);
}

#[tokio::test]
async fn oversized_pre_effect_input_does_not_lock_factory_or_consume_original() {
    let (mut f, mut operator, _, _) = fixture().await;
    f.post(original("ask3", &f.receiver.group)).await.unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let wire = reaction(&mut operator, &f, &target, "👍").await;
    let mut oversized = wire.clone();
    oversized.payload = vec![0; super::super::MAX_WIRE];
    assert_eq!(
        f.ingest(oversized).await.unwrap_err(),
        ReceiverHold::Capacity
    );
    assert!(!f.held);
    assert!(!f.receiver.latched);
    assert_eq!(f.ingest(wire).await.unwrap(), Some("ask3".into()));
    f.consume("ask3", &digest(b"exact source-only operation"))
        .unwrap();
}

#[tokio::test]
async fn removal_before_original_approval_is_retained_and_blocks_only_its_ask() {
    let (mut f, mut operator, file, _) = fixture().await;
    f.post(original("ask3", &f.receiver.group)).await.unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let approval = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![vec!["e".into(), target.clone()]],
        "👍",
    );
    // Native MLS sender generates approval first, but relay delivers its later
    // withdrawal first. Both wires go through the actual native decrypt path.
    let late_approval = reaction(&mut operator, &f, &target, "👍").await;
    let removal = app_wire(
        &mut operator,
        &f,
        MARMOT_APP_EVENT_KIND_DELETE,
        vec![vec!["e".into(), approval.id.to_ascii_uppercase()]],
        "",
    )
    .await;
    assert_eq!(f.ingest(removal).await.unwrap(), None);
    assert!(!f.held);
    assert!(
        std::fs::read_to_string(file.path())
            .unwrap()
            .contains("semantic-removal.v1")
    );
    assert_eq!(f.ingest(late_approval).await.unwrap(), None);
    assert!(f.asks["ask3"].conflicted);
    assert!(f.asks["ask3"].receipt.is_none());
    assert!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .is_err()
    );
    approve(&mut f, &mut operator, "ask2").await;
    f.consume("ask2", &digest(b"exact source-only operation"))
        .unwrap();
}

#[tokio::test]
async fn objection_before_positive_reaction_remains_terminal_and_order_independent() {
    let (mut f, mut operator, _, _) = fixture().await;
    f.post(original("ask3", &f.receiver.group)).await.unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let objection = reaction(&mut operator, &f, &target, "🛑").await;
    assert_eq!(f.ingest(objection).await.unwrap(), None);
    assert!(f.asks["ask3"].conflicted);
    let positive = reaction(&mut operator, &f, &target, "👍").await;
    assert_eq!(f.ingest(positive).await.unwrap(), None);
    assert!(f.asks["ask3"].receipt.is_none());
    assert!(!f.held);
}

#[tokio::test]
async fn hundred_scoped_terminal_conflicts_do_not_exhaust_unanswered_intake() {
    let (mut f, mut operator, _, _) = fixture().await;
    let alphabet = b"23456789abcdefghjkmnpqrstuvwxyz";
    for i in 0..100 {
        let id = format!(
            "ab{}{}",
            alphabet[i / alphabet.len()] as char,
            alphabet[i % alphabet.len()] as char
        );
        f.post(original(&id, &f.receiver.group)).await.unwrap();
        let objection = app_wire(
            &mut operator,
            &f,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            &format!("!answer {id} no"),
        )
        .await;
        assert_eq!(f.ingest(objection).await.unwrap(), None);
        assert!(f.asks[&id].conflicted);
    }
    assert_eq!(f.asks.len(), 100);
    assert!(f.asks.values().all(|a| a.conflicted && a.receipt.is_none()));
    approve(&mut f, &mut operator, "ask3").await;
    f.consume("ask3", &digest(b"exact source-only operation"))
        .unwrap();
}

#[tokio::test]
async fn duplicate_outbound_inner_ids_refuse_before_journal_send_or_latch() {
    let (mut f, mut operator, file, relay) = fixture().await;
    let mut ask = original("ask3", &f.receiver.group);
    ask.card_chunks = vec!["identical exact card".into(), "identical exact card".into()];
    assert_eq!(f.post(ask).await.unwrap_err(), ReceiverHold::ChangedState);
    assert!(!f.held);
    assert!(!f.receiver.latched);
    assert!(f.asks.is_empty());
    assert!(relay.wires.lock().unwrap().is_empty());
    assert_eq!(file.as_file().metadata().unwrap().len(), 0);
    approve(&mut f, &mut operator, "ask2").await;
    f.consume("ask2", &digest(b"exact source-only operation"))
        .unwrap();
}

#[tokio::test]
async fn edit_and_operator_removal_before_or_after_approval_cannot_leave_it_usable() {
    for kind in [MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_REMOVE] {
        for before in [true, false] {
            let (mut f, mut operator, _, _) = fixture().await;
            f.post(original("ask3", &f.receiver.group)).await.unwrap();
            let target = f.asks["ask3"].app_ids[0].clone();
            let event = MarmotAppEvent::new(
                hex::encode(operator.self_id().as_slice()),
                1,
                MARMOT_APP_EVENT_KIND_REACTION,
                vec![vec!["e".into(), target.clone()]],
                "👍",
            );
            let approval = reaction(&mut operator, &f, &target, "👍").await;
            let objection = app_wire(
                &mut operator,
                &f,
                kind,
                vec![vec!["e".into(), event.id]],
                "!answer ask3 no",
            )
            .await;
            if before {
                assert_eq!(f.ingest(objection).await.unwrap(), None);
                assert_eq!(f.ingest(approval).await.unwrap(), None);
            } else {
                assert_eq!(f.ingest(approval).await.unwrap(), Some("ask3".into()));
                assert_eq!(f.ingest(objection).await.unwrap(), None);
            }
            assert!(f.asks["ask3"].conflicted);
            assert!(!f.held);
            assert!(
                f.consume("ask3", &digest(b"exact source-only operation"))
                    .is_err()
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn ordered_actual_post_reply_and_consume_bind_native_card_to_independent_use_anchor() {
    let (mut factory, mut operator, _, _) = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (journal, _) = crate::protected_receiver::tests::ordered_fixture(
        root.path(),
        &factory.receiver.engine,
        &factory.receiver.group,
        &factory.receiver.operators,
    );
    factory.receiver.journal = crate::protected_receiver::ReceiverJournal::Ordered(journal);
    let ask = original("ask3", &factory.receiver.group);
    let operation_sha = digest(&ask.operation);
    factory.post(ask).await.unwrap();
    let target = factory.asks["ask3"].app_ids[0].clone();
    let wire = reaction(&mut operator, &factory, &target, "👍").await;
    assert_eq!(factory.ingest(wire).await.unwrap(), Some("ask3".into()));
    factory.consume("ask3", &operation_sha).unwrap();
    assert!(factory.consume("ask3", &operation_sha).is_err());
    let records = std::fs::read_to_string(root.path().join("receiver/journal"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let anchors = std::fs::read_to_string(root.path().join("consumer/anchor"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), anchors.len());
    let card = records
        .iter()
        .find(|r| r["body"]["kind"] == "card-complete")
        .unwrap();
    let consumed = records
        .iter()
        .find(|r| r["body"]["kind"] == "consumed")
        .unwrap();
    assert_eq!(card["body"]["original_operation_sha256"], operation_sha);
    assert_eq!(
        consumed["body"]["key"]["card_complete_sequence"],
        card["sequence"]
    );
    assert_eq!(
        consumed["body"]["key"]["original_operation_sha256"],
        operation_sha
    );
    assert_eq!(
        consumed["body"]["key"]["header_sha256"],
        records[0]["sha256"]
    );
    assert_eq!(anchors.last().unwrap()["use_key"], consumed["body"]["key"]);
}

#[cfg(unix)]
async fn finite_fixture() -> (
    SemanticFactory<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    tempfile::TempDir,
    Arc<Relay>,
) {
    finite_fixture_lifetime(100).await
}
#[cfg(unix)]
pub(super) async fn finite_fixture_lifetime(
    lifetime: u64,
) -> (
    SemanticFactory<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    tempfile::TempDir,
    Arc<Relay>,
) {
    use std::os::unix::fs::PermissionsExt;
    let (mut f, op, _, relay) = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!({"schema":"heterodyne-receiver-expiry.v1", "max_approval_lifetime_ms":lifetime})).unwrap();
    std::fs::write(root.path().join("profile"), &bytes).unwrap();
    std::fs::set_permissions(
        root.path().join("profile"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let (journal, _) = crate::protected_receiver::tests::ordered_fixture_profile(
        root.path(),
        &f.receiver.engine,
        &f.receiver.group,
        &f.receiver.operators,
        digest(&bytes),
    );
    f.receiver.journal = crate::protected_receiver::ReceiverJournal::Ordered(journal);
    let f = f
        .with_expiry_profile(std::fs::File::open(root.path().join("profile")).unwrap())
        .unwrap();
    (f, op, root, relay)
}
#[cfg(unix)]
pub(super) fn finite_original(id: &str, group: &cgka_traits::types::GroupId) -> OriginalAsk {
    let mut ask = original(id, group);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    ask.operation_canonical = serde_json::to_vec(&serde_json::json!({
        "schema":"heterodyne-protected-deployment.v1",
        "release":{"not_before_ns":now-1_000_000_000u128,"deadline_ns":now+60_000_000_000u128},
        "outage":{"not_before_ns":now-1_000_000_000u128,"deadline_ns":now+30_000_000_000u128,
            "recovery_deadline_ns":now+120_000_000_000u128}
    }))
    .unwrap(); // Only expiry extraction fixture; not full validated Product/custody evidence.
    ask
}
#[cfg(unix)]
#[tokio::test]
async fn finite_expiry_is_durable_and_late_response_does_not_revive_or_conflict() {
    let (mut f, mut op, root, _) = finite_fixture().await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let wire = reaction(&mut op, &f, &target, "👍").await;
    assert_eq!(f.ingest(wire).await.unwrap(), None);
    assert!(f.asks["ask3"].expired);
    assert!(!f.asks["ask3"].conflicted);
    assert!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .is_err()
    );
    f.post(finite_original("ask4", &f.receiver.group))
        .await
        .unwrap();
    let text = std::fs::read_to_string(root.path().join("receiver/journal")).unwrap();
    let sources: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["body"]["payload_hex"]
                .as_str()
                .map(|h| serde_json::from_slice(&hex::decode(h).unwrap()).unwrap())
        })
        .collect();
    let original = sources
        .iter()
        .find(|v| v["schema"] == "semantic-original.v2")
        .unwrap();
    assert!(original["expires_at_unix_ms"].as_u64().is_some());
    assert!(
        sources
            .iter()
            .any(|v| v["schema"] == "semantic-expired.v1" && v["ask_id"] == "ask3")
    );
}
#[cfg(unix)]
#[tokio::test]
async fn absent_finite_operation_or_changed_actual_profile_refuses_before_publish() {
    use std::os::unix::fs::PermissionsExt;
    let (mut f, _, root, relay) = finite_fixture().await;
    assert!(f.post(original("ask3", &f.receiver.group)).await.is_err());
    assert!(relay.wires.lock().unwrap().is_empty());
    assert!(!f.held);
    std::fs::set_permissions(
        root.path().join("profile"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(root.path().join("profile"), b"changed policy").unwrap();
    std::fs::set_permissions(
        root.path().join("profile"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    assert!(
        f.post(finite_original("ask3", &f.receiver.group))
            .await
            .is_err()
    );
    assert!(relay.wires.lock().unwrap().is_empty());
}

#[cfg(target_os = "linux")]
pub(super) fn cache(root: &std::path::Path, name: &str) -> std::fs::File {
    use std::os::unix::fs::DirBuilderExt;
    let path = root.join(name);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    std::fs::File::open(path).unwrap()
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_semantics_rebuilds_terminal_lookup_candidates_and_conflict_without_replaying_wire()
{
    let (mut f, mut op, root, relay) = finite_fixture_lifetime(20000).await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let wire = reaction(&mut op, &f, &target, "👍").await;
    f.ingest(wire).await.unwrap();
    let candidate = f.asks["ask3"]
        .receipt
        .as_ref()
        .unwrap()
        .authenticated_candidate
        .message_id
        .clone();
    let policy = f.policy().unwrap();
    let crate::protected_receiver::ReceiverJournal::Ordered(journal) = &f.receiver.journal else {
        panic!("ordered")
    };
    let catalog =
        catalog::Catalog::rebuild(journal, cache(root.path(), "cache1"), &policy, &f.endpoints)
            .unwrap();
    assert!(catalog.unanswered.is_empty());
    assert_eq!(
        catalog.ask(journal, "ask3").unwrap().unwrap().disposition,
        catalog::Disposition::Approved
    );
    assert!(catalog.candidate_seen(journal, &candidate).unwrap());
    assert_eq!(
        catalog.target(journal, &target).unwrap(),
        Some("ask3".into())
    );
    assert_eq!(relay.wires.lock().unwrap().len(), 2);
    let wire = reaction(&mut op, &f, &target, "👎").await;
    f.ingest(wire).await.unwrap();
    let crate::protected_receiver::ReceiverJournal::Ordered(journal) = &f.receiver.journal else {
        panic!("ordered")
    };
    assert!(catalog.ask(journal, "ask3").is_err()); // Stale derived checkpoint is never authority.
    let catalog =
        catalog::Catalog::rebuild(journal, cache(root.path(), "cache2"), &policy, &f.endpoints)
            .unwrap();
    assert_eq!(
        catalog.ask(journal, "ask3").unwrap().unwrap().disposition,
        catalog::Disposition::Conflicted
    );
    assert!(catalog.unanswered.is_empty());
    assert_eq!(relay.wires.lock().unwrap().len(), 2); // Rebuild performs no publishing.
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn unprojected_actual_contrary_candidate_cannot_restore_earlier_approval() {
    let (mut f, mut op, root, _) = finite_fixture_lifetime(20000).await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let yes = reaction(&mut op, &f, &target, "👍").await;
    f.ingest(yes).await.unwrap();
    let no = reaction(&mut op, &f, &target, "👎").await;
    assert!(f.receiver.ingest(no).await.unwrap().is_some()); // Actual native commit/outcome, crash before semantic projection.
    let policy = f.policy().unwrap();
    let crate::protected_receiver::ReceiverJournal::Ordered(journal) = &f.receiver.journal else {
        panic!("ordered")
    };
    assert!(
        catalog::Catalog::rebuild(journal, cache(root.path(), "cache"), &policy, &f.endpoints)
            .is_err()
    );
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_unrelated_removal_reconstructs_scoped_disk_tombstone() {
    let (mut f, mut op, root, _) = finite_fixture_lifetime(20000).await;
    let target = "ab".repeat(32);
    let wire = app_wire(
        &mut op,
        &f,
        MARMOT_APP_EVENT_KIND_DELETE,
        vec![vec!["e".into(), target.clone()]],
        "",
    )
    .await;
    assert_eq!(f.ingest(wire).await.unwrap(), None);
    let policy = f.policy().unwrap();
    let crate::protected_receiver::ReceiverJournal::Ordered(journal) = &f.receiver.journal else {
        panic!("ordered")
    };
    let catalog =
        catalog::Catalog::rebuild(journal, cache(root.path(), "cache"), &policy, &f.endpoints)
            .unwrap();
    assert!(
        catalog
            .removed(
                journal,
                &serde_json::to_value(op.self_id()).unwrap(),
                &target
            )
            .unwrap()
    );
    assert!(
        !catalog
            .removed(
                journal,
                &serde_json::to_value(cgka_traits::types::MemberId::new(vec![9; 32])).unwrap(),
                &target
            )
            .unwrap()
    );
}

#[cfg(target_os = "linux")]
fn recovery_owned_files(root: &std::path::Path) -> crate::protected_recovery::OwnedFiles {
    use std::os::unix::fs::OpenOptionsExt;
    let receiver = root.join("receiver");
    let consumer = root.join("consumer");
    std::fs::create_dir_all(&receiver).unwrap();
    std::fs::create_dir_all(&consumer).unwrap();
    let open = |p| {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(p)
            .unwrap()
    };
    crate::protected_recovery::OwnedFiles {
        journal: open(receiver.join("journal")),
        journal_directory: std::fs::File::open(&receiver).unwrap(),
        storage_lease: open(receiver.join("lease")),
        anchor: open(consumer.join("anchor")),
        anchor_directory: std::fs::File::open(&consumer).unwrap(),
    }
}
#[cfg(target_os = "linux")]
async fn fresh_recovery_factory() -> (
    SemanticFactory<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    tempfile::TempDir,
    Arc<Relay>,
) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut operator = client(b"semantic-operator");
    let mut controller = client(b"semantic-controller");
    let mut kp = controller.fresh_key_package().await.unwrap();
    kp.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: cgka_traits::types::MessageId::new(vec![4; 32]),
    });
    let route = NostrRoutingV1::new([7; 32], vec!["wss://semantic.invalid".into()]).unwrap();
    let (group, created) = operator
        .create_group(CreateGroupRequest {
            name: "recovery".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&route).unwrap(),
            }],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = created
    else {
        panic!("fixture")
    };
    operator.confirm_published(pending).await.unwrap();
    operator.drain_events();
    controller.drain_events();
    let root = tempfile::tempdir().unwrap();
    let intent = crate::protected_join::JoinIntent {
        file: std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(root.path().join("join-intent"))
            .unwrap(),
        directory: std::fs::File::open(root.path()).unwrap(),
    };
    let join = controller
        .receiver_join_owned(welcomes.remove(0), intent)
        .await
        .unwrap();
    let profile=serde_json::to_vec(&serde_json::json!({"schema":"heterodyne-receiver-expiry.v1","max_approval_lifetime_ms":30000})).unwrap();
    std::fs::write(root.path().join("profile"), &profile).unwrap();
    std::fs::set_permissions(
        root.path().join("profile"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let enrollment = crate::protected_recovery::Enrollment {
        schema: "heterodyne-receiver-enrollment.v2".into(),
        expiry_profile_sha256: digest(&profile),
        account: hex::encode(controller.self_id().as_slice()),
        group: hex::encode(group.as_slice()),
        operators: vec![hex::encode(operator.self_id().as_slice())],
        source_profile_sha256: "55".repeat(32),
        storage_generation: "66".repeat(32),
        initial_native_state_sha256: digest(&serde_json::to_vec(&join.joined).unwrap()),
        welcome_provenance_sha256: join.digest().unwrap(),
    };
    let journal =
        crate::protected_recovery::Journal::enroll(recovery_owned_files(root.path()), enrollment)
            .unwrap();
    let receiver = ProtectedReceiver::from_native_join(
        controller,
        group,
        vec![operator.self_id()],
        journal,
        join,
    )
    .unwrap();
    let relay = Arc::new(Relay::default());
    let transport = NostrTransportAdapter::new(relay.clone());
    transport
        .activate_account(TransportAccountActivation {
            account_id: receiver.engine.self_id(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    let mut factory = SemanticFactory::new(
        receiver,
        transport,
        vec![TransportEndpoint::from("wss://semantic.invalid")],
    )
    .unwrap()
    .with_expiry_profile(std::fs::File::open(root.path().join("profile")).unwrap())
    .unwrap();
    factory
        .enable_catalog(cache(root.path(), "initial-cache"))
        .unwrap();
    (factory, operator, root, relay)
}
#[cfg(target_os = "linux")]
async fn restart_factory(
    f: SemanticFactory<SqliteAccountStorage>,
    root: &std::path::Path,
    relay: Arc<Relay>,
    cache_name: &str,
) -> Result<SemanticFactory<SqliteAccountStorage>, ReceiverHold> {
    let storage = f.receiver.engine.storage.clone();
    let group = f.receiver.group.clone();
    let operators = f.receiver.operators.clone();
    let enrollment = f.ordered().unwrap().enrollment().unwrap();
    drop(f);
    // Real Engine rehydration from the same actual SQLite account state. Fixture
    // signer/peeler identities are synthetic; no production custody is asserted.
    let engine = restart_client(b"semantic-controller", storage);
    let journal =
        crate::protected_recovery::Journal::reopen(recovery_owned_files(root), &enrollment)
            .map_err(|_| ReceiverHold::Journal)?;
    let transport = NostrTransportAdapter::new(relay);
    transport
        .activate_account(TransportAccountActivation {
            account_id: engine.self_id(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    SemanticFactory::reopen(
        engine,
        group,
        operators,
        journal,
        transport,
        vec![TransportEndpoint::from("wss://semantic.invalid")],
        super::reopen::ReopenFiles {
            expiry: std::fs::File::open(root.join("profile")).unwrap(),
            cache: cache(root, cache_name),
        },
    )
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_approval_restart_consumes_once_and_continues_unanswered() {
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let yes = reaction(&mut op, &f, &target, "👍").await;
    f.ingest(yes).await.unwrap();
    let published = relay.wires.lock().unwrap().len();
    let mut f = restart_factory(f, root.path(), relay.clone(), "restart1")
        .await
        .unwrap();
    assert!(f.asks.is_empty());
    assert_eq!(relay.wires.lock().unwrap().len(), published);
    assert_eq!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .unwrap()
            .decision,
        Decision::Approve
    );
    let mut f = restart_factory(f, root.path(), relay.clone(), "restart2")
        .await
        .unwrap();
    assert!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .is_err()
    );
    f.post(finite_original("ask4", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask4"].app_ids[0].clone();
    let mut f = restart_factory(f, root.path(), relay.clone(), "restart3")
        .await
        .unwrap();
    assert_eq!(f.asks.len(), 1);
    assert!(f.asks.contains_key("ask4"));
    let yes = reaction(&mut op, &f, &target, "👍").await;
    f.ingest(yes).await.unwrap();
    f.consume("ask4", &digest(b"exact source-only operation"))
        .unwrap();
    assert_eq!(f.catalog.as_ref().unwrap().unanswered.len(), 0);
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_restart_contrary_and_removal_preserve_scoped_conflicts() {
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let yes = reaction(&mut op, &f, &target, "👍").await;
    f.ingest(yes).await.unwrap();
    let mut f = restart_factory(f, root.path(), relay.clone(), "restart1")
        .await
        .unwrap();
    let no = reaction(&mut op, &f, &target, "👎").await;
    f.ingest(no).await.unwrap();
    assert!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .is_err()
    );
    f.post(finite_original("ask4", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask4"].app_ids[0].clone();
    let yes = reaction(&mut op, &f, &target, "👍").await;
    f.ingest(yes).await.unwrap();
    let inner = f.asks["ask4"]
        .receipt
        .as_ref()
        .unwrap()
        .authenticated_candidate
        .application
        .id
        .clone();
    let mut f = restart_factory(f, root.path(), relay.clone(), "restart2")
        .await
        .unwrap();
    let remove = app_wire(
        &mut op,
        &f,
        MARMOT_APP_EVENT_KIND_DELETE,
        vec![vec!["e".into(), inner]],
        "",
    )
    .await;
    f.ingest(remove).await.unwrap();
    let mut f = restart_factory(f, root.path(), relay.clone(), "restart3")
        .await
        .unwrap();
    assert!(
        f.consume("ask4", &digest(b"exact source-only operation"))
            .is_err()
    );
    f.post(finite_original("ask5", &f.receiver.group))
        .await
        .unwrap();
    assert_eq!(f.catalog.as_ref().unwrap().unanswered.len(), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_disk_targets_ignore_unrelated_reaction_and_scope_multiask_removal() {
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    let mut cards = Vec::new();
    let mut inner = String::new();
    for id in ["ask3", "ask4"] {
        f.post(finite_original(id, &f.receiver.group))
            .await
            .unwrap();
        let target = f.asks[id].app_ids[0].clone();
        let yes = reaction(&mut op, &f, &target, "👍").await;
        f.ingest(yes).await.unwrap();
        inner = f.asks[id]
            .receipt
            .as_ref()
            .unwrap()
            .authenticated_candidate
            .application
            .id
            .clone();
        cards.push(target);
    }
    let mut f = restart_factory(f, root.path(), relay.clone(), "restart1")
        .await
        .unwrap();
    // A reaction to a decision is not a reaction to its original card. The
    // terminal lookup must not reinterpret that reference as another consent.
    let unrelated = reaction(&mut op, &f, &inner, "👎").await;
    f.ingest(unrelated).await.unwrap();
    assert!(!f.held);
    assert!(f.asks.is_empty());
    assert_eq!(
        f.catalog
            .as_ref()
            .unwrap()
            .retained_ask("ask4")
            .unwrap()
            .unwrap()
            .disposition,
        catalog::Disposition::Approved
    );
    // One actual message targeting two known cards makes a bounded, durable
    // scoped conflict without loading both historical full-card payloads.
    let remove = app_wire(
        &mut op,
        &f,
        MARMOT_APP_EVENT_KIND_DELETE,
        cards.into_iter().map(|id| vec!["e".into(), id]).collect(),
        "",
    )
    .await;
    f.ingest(remove).await.unwrap();
    assert!(!f.held);
    assert!(f.asks.is_empty());
    let mut f = restart_factory(f, root.path(), relay, "restart2")
        .await
        .unwrap();
    for id in ["ask3", "ask4"] {
        assert!(
            f.consume(id, &digest(b"exact source-only operation"))
                .is_err()
        );
    }
    f.post(finite_original("ask5", &f.receiver.group))
        .await
        .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_final_native_reply_is_classified_once_without_reingest() {
    for contrary in [false, true] {
        let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
        f.post(finite_original("ask3", &f.receiver.group))
            .await
            .unwrap();
        let target = f.asks["ask3"].app_ids[0].clone();
        if contrary {
            let yes = reaction(&mut op, &f, &target, "👍").await;
            f.ingest(yes).await.unwrap();
        }
        let reply = reaction(&mut op, &f, &target, if contrary { "👎" } else { "👍" }).await;
        // Actual native ingest + complete anchored outcome, then crash before
        // its semantic projection. The retained wire must never be re-ingested.
        f.receiver.ingest(reply).await.unwrap().unwrap();
        let sequence = f.receiver.sequence;
        let published = relay.wires.lock().unwrap().len();
        let mut f = restart_factory(f, root.path(), relay.clone(), "restart1")
            .await
            .unwrap();
        assert_eq!(f.receiver.sequence, sequence);
        assert_eq!(relay.wires.lock().unwrap().len(), published);
        if contrary {
            assert!(
                f.consume("ask3", &digest(b"exact source-only operation"))
                    .is_err()
            );
        } else {
            f.consume("ask3", &digest(b"exact source-only operation"))
                .unwrap();
        }
        let mut f = restart_factory(f, root.path(), relay, "restart2")
            .await
            .unwrap();
        assert!(
            f.consume("ask3", &digest(b"exact source-only operation"))
                .is_err()
        );
    }
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_refuses_unretained_native_plaintext_and_partial_publication() {
    use cgka_traits::MessageStorage;
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let reply = reaction(&mut op, &f, &target, "👍").await;
    f.receiver.engine.ingest(reply).await.unwrap(); // Deliberately outside owned ingress.
    let storage = f.receiver.engine.storage.clone();
    let pending = storage.list_pending_application_events().unwrap();
    assert!(!pending.is_empty());
    assert!(
        restart_factory(f, root.path(), relay, "restart1")
            .await
            .is_err()
    );
    assert_eq!(
        storage.list_pending_application_events().unwrap().len(),
        pending.len()
    );
    let (mut f, _, root, relay) = fresh_recovery_factory().await;
    *relay.fail_at.lock().unwrap() = Some(1);
    assert!(
        f.post(finite_original("ask3", &f.receiver.group))
            .await
            .is_err()
    );
    let published = relay.wires.lock().unwrap().len();
    assert!(
        restart_factory(f, root.path(), relay.clone(), "restart1")
            .await
            .is_err()
    );
    assert_eq!(relay.wires.lock().unwrap().len(), published);
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_expiry_is_not_extended_by_restart() {
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    let mut original = finite_original("ask3", &f.receiver.group);
    let mut value: serde_json::Value =
        serde_json::from_slice(&original.operation_canonical).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    value["outage"]["deadline_ns"] = serde_json::json!(now + 2_000_000_000u128);
    original.operation_canonical = serde_json::to_vec(&value).unwrap();
    f.post(original).await.unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let original_expiry = f.asks["ask3"].expires_at_unix_ms;
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    let mut f = restart_factory(f, root.path(), relay, "restart1")
        .await
        .unwrap();
    assert_eq!(f.asks["ask3"].expires_at_unix_ms, original_expiry);
    assert!(f.asks["ask3"].expired);
    assert!(f.catalog.as_ref().unwrap().unanswered.is_empty());
    let yes = reaction(&mut op, &f, &target, "👍").await;
    assert!(f.ingest(yes).await.unwrap().is_none());
    assert!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_reopens_only_retained_direct_unchanged_policy_update() {
    for retained in [true, false] {
        let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
        let SendResult::GroupEvolution { msg, pending, .. } = op
            .send(SendIntent::SelfUpdate {
                group_id: f.receiver.group.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("update")
        };
        op.confirm_published(pending).await.unwrap();
        op.drain_events();
        if retained {
            assert!(f.ingest(msg).await.unwrap().is_none());
        } else {
            f.receiver.engine.ingest(msg).await.unwrap();
        }
        let result = restart_factory(f, root.path(), relay, "restart1").await;
        if retained {
            let mut f = result.unwrap();
            f.post(finite_original("ask3", &f.receiver.group))
                .await
                .unwrap();
            let target = f.asks["ask3"].app_ids[0].clone();
            let yes = reaction(&mut op, &f, &target, "👍").await;
            f.ingest(yes).await.unwrap();
            f.consume("ask3", &digest(b"exact source-only operation"))
                .unwrap();
        } else {
            assert!(result.is_err());
        }
    }
}

#[cfg(target_os = "linux")]
fn short_original(id: &str, group: &cgka_traits::types::GroupId, lifetime_ms: u64) -> OriginalAsk {
    let mut original = finite_original(id, group);
    let mut value: serde_json::Value =
        serde_json::from_slice(&original.operation_canonical).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    value["outage"]["deadline_ns"] = serde_json::json!(now + u128::from(lifetime_ms) * 1_000_000);
    original.operation_canonical = serde_json::to_vec(&value).unwrap();
    original
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_checked_time_survives_original_write_crossing_expiry() {
    let (mut f, _, root, relay) = fresh_recovery_factory().await;
    f.record_delay = std::time::Duration::from_millis(2200);
    let original = short_original("ask3", &f.receiver.group, 1800);
    f.post(original).await.unwrap();
    f.record_delay = std::time::Duration::ZERO;
    let mut f = restart_factory(f, root.path(), relay, "restart1")
        .await
        .unwrap();
    assert!(f.asks["ask3"].expired);
    assert!(!f.held);
    f.post(finite_original("ask4", &f.receiver.group))
        .await
        .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_checked_time_preserves_consumed_and_denied_after_expiry() {
    for deny in [false, true] {
        let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
        f.post(short_original("ask3", &f.receiver.group, 4000))
            .await
            .unwrap();
        let target = f.asks["ask3"].app_ids[0].clone();
        let reply = reaction(&mut op, &f, &target, if deny { "👎" } else { "👍" }).await;
        f.ingest(reply).await.unwrap();
        if deny {
            tokio::time::sleep(std::time::Duration::from_millis(4100)).await;
        } else {
            f.record_delay = std::time::Duration::from_millis(4100);
            f.consume("ask3", &digest(b"exact source-only operation"))
                .unwrap();
            f.record_delay = std::time::Duration::ZERO;
        }
        let mut f = restart_factory(f, root.path(), relay.clone(), "restart1")
            .await
            .unwrap();
        let view = f
            .catalog
            .as_ref()
            .unwrap()
            .ask(f.ordered().unwrap(), "ask3")
            .unwrap()
            .unwrap();
        assert_eq!(
            view.disposition,
            if deny {
                catalog::Disposition::Denied
            } else {
                catalog::Disposition::Consumed
            }
        );
        assert!(
            f.consume("ask3", &digest(b"exact source-only operation"))
                .is_err()
        );
        assert!(!f.held);
        if !deny {
            let contrary = reaction(&mut op, &f, &target, "👎").await;
            f.ingest(contrary).await.unwrap();
            let view = f
                .catalog
                .as_ref()
                .unwrap()
                .ask(f.ordered().unwrap(), "ask3")
                .unwrap()
                .unwrap();
            assert!(
                view.conflicted,
                "consumed consent retains contrary evidence after expiry"
            );
            assert!(view.consumed);
        }
        f.post(finite_original("ask4", &f.receiver.group))
            .await
            .unwrap();
        restart_factory(f, root.path(), relay, "restart2")
            .await
            .unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_unprojected_reply_expires_during_downtime_without_poisoning() {
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    f.post(short_original("ask3", &f.receiver.group, 1800))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let yes = reaction(&mut op, &f, &target, "👍").await;
    f.receiver.ingest(yes).await.unwrap().unwrap();
    let sequence = f.receiver.sequence;
    tokio::time::sleep(std::time::Duration::from_millis(1900)).await;
    let mut f = restart_factory(f, root.path(), relay, "restart1")
        .await
        .unwrap();
    assert_eq!(f.receiver.sequence, sequence);
    let mut cursor = f.ordered().unwrap().source_cursor().unwrap();
    while let Some(record) = cursor.next().unwrap() {
        assert_ne!(
            record.body["schema"], "semantic-decision.v1",
            "late recovered reply must never record a decision"
        );
    }
    assert!(
        f.consume("ask3", &digest(b"exact source-only operation"))
            .is_err()
    );
    assert!(!f.held);
    f.post(finite_original("ask4", &f.receiver.group))
        .await
        .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_multicard_removal_retains_early_third_approval_tombstone() {
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    for id in ["ask3", "ask4", "ask5"] {
        f.post(finite_original(id, &f.receiver.group))
            .await
            .unwrap();
    }
    let target = f.asks["ask5"].app_ids[0].clone();
    let early = MarmotAppEvent::new(
        hex::encode(op.self_id().as_slice()),
        1,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![vec!["e".into(), target]],
        "👍",
    );
    let deletion = app_wire(
        &mut op,
        &f,
        MARMOT_APP_EVENT_KIND_DELETE,
        vec![
            vec!["e".into(), f.asks["ask3"].app_ids[0].clone()],
            vec!["e".into(), f.asks["ask4"].app_ids[0].clone()],
            vec!["e".into(), early.id.clone()],
        ],
        "",
    )
    .await;
    assert!(f.ingest(deletion).await.unwrap().is_none());
    let SendResult::ApplicationMessage { msg, .. } = op
        .send(SendIntent::AppMessage {
            group_id: f.receiver.group.clone(),
            payload: early.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("application");
    };
    assert!(f.ingest(msg).await.unwrap().is_none());
    let mut f = restart_factory(f, root.path(), relay, "restart1")
        .await
        .unwrap();
    assert!(
        f.consume("ask5", &digest(b"exact source-only operation"))
            .is_err()
    );
    assert!(!f.held);
    f.post(finite_original("ask6", &f.receiver.group))
        .await
        .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_expiry_preserves_outer_classification_hold() {
    let (mut f, mut op, _root, relay) = fresh_recovery_factory().await;
    f.post(short_original("ask3", &f.receiver.group, 1800))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let reply = reaction(&mut op, &f, &target, "👍").await;
    let candidate = f.receiver.ingest(reply).await.unwrap().unwrap();
    // An actual native outcome reaches the duplicate guard after time crosses
    // expiry during the outer classification boundary. No candidate is forged.
    f.seen_candidates.insert(candidate.message_id.clone());
    f.held = true;
    tokio::time::sleep(std::time::Duration::from_millis(1900)).await;
    assert!(matches!(
        f.classify(candidate),
        Err(ReceiverHold::ChangedState)
    ));
    assert!(f.asks["ask3"].expired);
    assert!(f.held, "expiry cannot erase the enclosing hold on failure");
    let published = relay.wires.lock().unwrap().len();
    assert!(matches!(
        f.post(finite_original("ask4", &f.receiver.group)).await,
        Err(ReceiverHold::Latched)
    ));
    assert_eq!(relay.wires.lock().unwrap().len(), published);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_owner_unknown_pending_refuses_before_recovered_decision_write() {
    use cgka_traits::MessageStorage;
    let (mut f, mut op, root, relay) = fresh_recovery_factory().await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let reply = reaction(&mut op, &f, &target, "👍").await;
    // Complete actual owned native ingress, interrupted before semantic decision.
    f.receiver.ingest(reply).await.unwrap().unwrap();
    let extra = app_wire(&mut op, &f, MARMOT_APP_EVENT_KIND_CHAT, vec![], "unowned").await;
    f.receiver.engine.ingest(extra).await.unwrap();
    let storage = f.receiver.engine.storage.clone();
    let pending = serde_json::to_vec(&storage.list_pending_application_events().unwrap()).unwrap();
    let journal = std::fs::read(root.path().join("receiver/journal")).unwrap();
    let anchor = std::fs::read(root.path().join("consumer/anchor")).unwrap();
    let published = relay.wires.lock().unwrap().len();
    assert!(matches!(
        restart_factory(f, root.path(), relay.clone(), "unknown-pending").await,
        Err(ReceiverHold::ChangedState)
    ));
    assert_eq!(
        std::fs::read(root.path().join("receiver/journal")).unwrap(),
        journal
    );
    assert_eq!(
        std::fs::read(root.path().join("consumer/anchor")).unwrap(),
        anchor
    );
    assert_eq!(
        serde_json::to_vec(&storage.list_pending_application_events().unwrap()).unwrap(),
        pending,
        "unknown native data must remain intact"
    );
    assert_eq!(relay.wires.lock().unwrap().len(), published);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn altered_terminal_cache_cannot_borrow_another_asks_approval() {
    let (mut f, mut operator, root, relay) = fresh_recovery_factory().await;
    for id in ["ask3", "ask4"] {
        f.post(finite_original(id, &f.receiver.group))
            .await
            .unwrap();
        let target = f.asks[id].app_ids[0].clone();
        let yes = reaction(&mut operator, &f, &target, "👍").await;
        f.ingest(yes).await.unwrap();
    }
    let catalog = f.catalog.as_ref().unwrap();
    let ask3 = catalog.retained_ask("ask3").unwrap().unwrap();
    let ask4 = catalog.retained_ask("ask4").unwrap().unwrap();
    let path = root.path().join("initial-cache").join(digest(b"ask\0ask3"));
    let correct = std::fs::read(&path).unwrap();
    let journal = std::fs::read(root.path().join("receiver/journal")).unwrap();
    let anchor = std::fs::read(root.path().join("consumer/anchor")).unwrap();
    let published = relay.wires.lock().unwrap().len();
    for mode in 0..3 {
        let mut altered = serde_json::to_value(&ask3).unwrap();
        match mode {
            0 => altered["decision_sequence"] = serde_json::json!(ask4.decision_sequence),
            1 => altered["original_sequence"] = serde_json::json!(ask4.original_sequence),
            _ => altered["id"] = serde_json::json!("ask4"),
        }
        std::fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
        f.asks.clear();
        assert!(matches!(
            f.consume("ask3", &ask3.original_sha256),
            Err(ReceiverHold::ChangedState)
        ));
        assert_eq!(
            std::fs::read(root.path().join("receiver/journal")).unwrap(),
            journal
        );
        assert_eq!(
            std::fs::read(root.path().join("consumer/anchor")).unwrap(),
            anchor
        );
        assert_eq!(relay.wires.lock().unwrap().len(), published);
    }
    std::fs::write(path, correct).unwrap();
    f.asks.clear();
    f.consume("ask3", &ask3.original_sha256).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn changed_candidate_plaintext_refuses_reopen_without_ack_or_projection() {
    use cgka_traits::MessageStorage;
    let (mut f, mut operator, root, relay) = fresh_recovery_factory().await;
    f.post(finite_original("ask3", &f.receiver.group))
        .await
        .unwrap();
    let target = f.asks["ask3"].app_ids[0].clone();
    let no = reaction(&mut operator, &f, &target, "👎").await;
    let received = f.ordered().unwrap().checked_now().unwrap();
    // Deliberately corrupt the private recording boundary in this fixture only:
    // real native MLS authenticates NO, but retained candidate claims YES.
    let outcome = f.receiver.engine.ingest(no.clone()).await.unwrap();
    let events = f.receiver.engine.drain_events();
    let event = events
        .iter()
        .find(|e| matches!(e, cgka_traits::GroupEvent::MessageReceived { .. }))
        .unwrap();
    let projection = super::super::PendingApplicationProjection::capture(event).unwrap();
    let cgka_traits::GroupEvent::MessageReceived {
        group_id,
        message_id,
        sender,
        epoch,
        payload,
        ..
    } = event
    else {
        unreachable!()
    };
    let actual = MarmotAppEvent::decode(payload).unwrap();
    let changed = MarmotAppEvent::new(
        actual.pubkey.clone(),
        actual.created_at,
        actual.kind,
        actual.tags.clone(),
        "👍",
    );
    assert_ne!(actual, changed);
    let candidate = serde_json::json!({"sequence":1,"received_at_unix_ms":received,"group":group_id,
        "message_id":hex::encode(message_id.as_slice()),"source_epoch":epoch.0,"sender":sender,"application":changed});
    f.receiver.record(serde_json::json!({"schema":"receiver-wire.v1","sequence":1,"received_at_unix_ms":received,"wire":no})).unwrap();
    f.receiver.record(serde_json::json!({"schema":"receiver-outcome.v1","sequence":1,"message_id":hex::encode(no.id.as_slice()),
        "outcome":outcome,"candidate":candidate,"pending_application_ids":[message_id],
        "pending_application_projections":[projection],"native_merge":null})).unwrap();
    let storage = f.receiver.engine.storage.clone();
    let before = serde_json::to_vec(&storage.list_pending_application_events().unwrap()).unwrap();
    let journal = std::fs::read(root.path().join("receiver/journal")).unwrap();
    let anchor = std::fs::read(root.path().join("consumer/anchor")).unwrap();
    let published = relay.wires.lock().unwrap().len();
    assert!(matches!(
        restart_factory(f, root.path(), relay.clone(), "forged-cache").await,
        Err(ReceiverHold::ChangedState)
    ));
    assert_eq!(
        std::fs::read(root.path().join("receiver/journal")).unwrap(),
        journal
    );
    assert_eq!(
        std::fs::read(root.path().join("consumer/anchor")).unwrap(),
        anchor
    );
    assert_eq!(
        serde_json::to_vec(&storage.list_pending_application_events().unwrap()).unwrap(),
        before
    );
    assert_eq!(relay.wires.lock().unwrap().len(), published);
}
