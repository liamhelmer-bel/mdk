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
struct Relay {
    wires: Mutex<Vec<TransportMessage>>,
    fail_at: Mutex<Option<usize>>,
}
#[async_trait::async_trait]
impl NostrRelayClient for Relay {
    async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
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
fn client(seed: &[u8]) -> Engine<SqliteAccountStorage> {
    let (engine, _) = build_client(seed);
    // Reuse actual Engine identity/signature fixture, but real kind-445/NIP59 peeler.
    let storage = engine.storage.clone();
    let mut supported = default_group_components();
    supported.insert(NOSTR_ROUTING_COMPONENT_ID);
    crate::EngineBuilder::new(storage)
        .supported_app_components(supported)
        .legacy_compatibility_profile()
        .identity(engine.self_id().as_slice().to_vec())
        .account_identity_proof_signer(Arc::new(
            crate::distributed_convergence::tests::TestProofSigner(key(seed)),
        ))
        .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(
            nostr::Keys::parse(&hex::encode(key(seed).to_bytes())).unwrap(),
        )))
        .build()
        .unwrap()
}
async fn fixture() -> (
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
fn original(id: &str, group: &cgka_traits::types::GroupId) -> OriginalAsk {
    OriginalAsk {
        ask_id: id.into(),
        expected_group: group.clone(),
        operation: b"exact source-only operation".to_vec(),
        operation_canonical: b"canonical source-only operation".to_vec(),
        original_request: b"exact original admind input bytes".to_vec(),
        card_chunks: vec![
            "existing producer exact card part one".into(),
            "existing producer exact card part two".into(),
        ],
    }
}
async fn reaction(
    operator: &mut Engine<SqliteAccountStorage>,
    factory: &SemanticFactory<SqliteAccountStorage>,
    target: &str,
    emoji: &str,
) -> TransportMessage {
    let app = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![vec!["e".into(), target.into()]],
        emoji,
    );
    let SendResult::ApplicationMessage { msg, .. } = operator
        .send(SendIntent::AppMessage {
            group_id: factory.receiver.group.clone(),
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
    assert!(f.post(original("ask2", &f.receiver.group)).await.is_err());
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
