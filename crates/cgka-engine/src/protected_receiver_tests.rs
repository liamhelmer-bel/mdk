use super::*;
use crate::distributed_convergence::tests::{PassthroughPeeler, TestProofSigner};
use crate::provider::EngineOpenMlsProvider;
use crate::{DEFAULT_CIPHERSUITE, EngineBuilder};
use cgka_traits::{
    engine::{CreateGroupRequest, SendIntent, SendResult},
    types::MessageId,
};
use cgka_traits::{
    storage::AccountDeviceSignerStorage,
    transport::{Timestamp, TransportEnvelope, TransportSource},
};
use openmls::group::MlsGroup;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;
use tls_codec::Serialize as _;

pub(super) fn key(seed: &[u8]) -> k256::schnorr::SigningKey {
    for counter in 0u64.. {
        let mut hash = Sha256::new();
        hash.update(seed);
        hash.update(counter.to_be_bytes());
        if let Ok(key) = k256::schnorr::SigningKey::from_bytes(&hash.finalize()) {
            return key;
        }
    }
    unreachable!()
}
fn pad32(seed: &[u8]) -> Vec<u8> {
    key(seed).verifying_key().to_bytes().to_vec()
}
pub(super) fn build_client(seed: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(seed))
        .account_identity_proof_signer(std::sync::Arc::new(TestProofSigner(key(seed))))
        .peeler(Box::new(PassthroughPeeler))
        .build()
        .unwrap();
    (engine, storage)
}
fn hash_id(bytes: &[u8]) -> MessageId {
    crate::message_processor::content_dedup_id(bytes)
}
fn welcome_for(welcomes: &[TransportMessage], seed: &[u8]) -> TransportMessage {
    welcomes.iter().find(|m|matches!(&m.envelope,TransportEnvelope::Welcome{recipient} if recipient.as_slice()==pad32(seed)))
        .unwrap().clone()
}
async fn send_app(
    engine: &mut Engine<SqliteAccountStorage>,
    group: &GroupId,
    content: Vec<u8>,
) -> TransportMessage {
    let payload = MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        String::from_utf8(content).unwrap(),
    )
    .encode()
    .unwrap();
    let SendResult::ApplicationMessage { mut msg, .. } = engine
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("application")
    };
    msg.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    msg
}

fn raw_app_message_with_payload(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    payload: &[u8],
) -> TransportMessage {
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_gid)
        .expect("load sender MLS group")
        .expect("sender joined group");
    let binding = storage
        .account_device_signer(sender)
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists");
    let msg = mls_group
        .create_message(&provider, &signer, payload)
        .expect("raw OpenMLS application message");
    let payload = msg
        .tls_serialize_detached()
        .expect("serialize raw app message");
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("raw-openmls-app".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    }
}

async fn fixture() -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    Engine<SqliteAccountStorage>,
    GroupId,
) {
    let (mut alice, storage) = build_client(b"receiver-alice");
    let (mut bob, _) = build_client(b"receiver-bob");
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "receiver".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("legacy fixture");
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"receiver-bob"))
        .await
        .unwrap();
    alice.drain_events();
    bob.drain_events();
    (alice, storage, bob, group)
}

fn records(file: &tempfile::NamedTempFile) -> Vec<serde_json::Value> {
    std::fs::read_to_string(file.path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn receiver_authenticates_real_mls_and_journals_original_before_candidate() {
    let (mut alice, _, bob, group) = fixture().await;
    let mut wire = send_app(&mut alice, &group, b"approve exact ask".to_vec()).await;
    wire.id = MessageId::new(vec![0x55; 32]); // Outer ID is not the canonical MLS content ID.
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver =
        ProtectedReceiver::new(bob, group, vec![alice.self_id()], file.reopen().unwrap()).unwrap();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert!(receiver.ingest(wire.clone()).await.unwrap().is_some());
    let log = records(&file);
    assert_eq!(log.len(), 2);
    assert_ne!(
        log[1]["candidate"]["message_id"],
        hex::encode(wire.id.as_slice())
    );
    assert_eq!(
        log[1]["candidate"]["message_id"],
        hex::encode(crate::message_processor::content_dedup_id(&wire.payload).as_slice())
    );
    assert_eq!(log[0]["wire"], serde_json::to_value(&wire).unwrap());
    assert!(log[0]["received_at_unix_ms"].as_u64().unwrap() as u128 >= before);
    assert_eq!(
        log[1]["candidate"]["application"]["content"],
        "approve exact ask"
    );
    assert_eq!(
        log[1]["candidate"]["application"]["pubkey"],
        hex::encode(alice.self_id().as_slice())
    );
    wire.id = MessageId::new(vec![0x66; 32]); // Fresh wrapper still has duplicate MLS bytes.
    assert!(
        receiver.ingest(wire).await.unwrap().is_none(),
        "duplicate cannot issue another candidate"
    );
    assert_eq!(records(&file).len(), 4);
}

#[tokio::test]
async fn receiver_drops_nonoperator_without_trusting_inner_pubkey_or_transport_time() {
    let (mut alice, _, bob, group) = fixture().await;
    let wire = send_app(&mut alice, &group, b"approve".to_vec()).await;
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver = ProtectedReceiver::new(
        bob,
        group,
        vec![MemberId::new(pad32(b"other"))],
        file.reopen().unwrap(),
    )
    .unwrap();
    assert!(receiver.ingest(wire).await.unwrap().is_none());
    assert!(records(&file)[1]["candidate"].is_null());
}

#[tokio::test]
async fn receiver_rejects_authentic_mls_with_forged_inner_operator_identity() {
    let (alice, storage, bob, group) = fixture().await;
    let forged = MemberId::new(pad32(b"other"));
    let payload = MarmotAppEvent::new(
        hex::encode(forged.as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "approve",
    )
    .encode()
    .unwrap();
    let wire = raw_app_message_with_payload(&storage, &alice.self_id(), &group, &payload);
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver =
        ProtectedReceiver::new(bob, group, vec![alice.self_id()], file.reopen().unwrap()).unwrap();
    let result = receiver.ingest(wire.clone()).await;
    assert!(
        matches!(result, Ok(None)),
        "native sender validation must reject without producing a candidate: {result:?}"
    );
    assert_eq!(
        records(&file)[1]["outcome"],
        serde_json::json!({"Ignored":{"category":"InvalidEncoding"}})
    );
    assert!(records(&file)[1]["candidate"].is_null());
    assert_eq!(
        records(&file)[0]["wire"],
        serde_json::to_value(&wire).unwrap()
    );
    assert!(!receiver.latched);
    assert!(
        records(&file)
            .iter()
            .all(|v| v.get("candidate").is_none_or(|v| v.is_null()))
    );
}

#[tokio::test]
async fn receiver_journal_failure_latches_before_real_engine_ingest() {
    let (mut alice, _, bob, group) = fixture().await;
    let wire = send_app(&mut alice, &group, b"approve".to_vec()).await;
    let file = tempfile::NamedTempFile::new().unwrap();
    let readonly = std::fs::File::open(file.path()).unwrap();
    let mut receiver = ProtectedReceiver::new(bob, group, vec![alice.self_id()], readonly).unwrap();
    assert_eq!(
        receiver.ingest(wire.clone()).await.unwrap_err(),
        ReceiverHold::Journal
    );
    assert_eq!(
        receiver.ingest(wire).await.unwrap_err(),
        ReceiverHold::Latched
    );
    assert!(records(&file).is_empty());
}

#[tokio::test]
async fn receiver_refuses_reopening_unreconciled_original_wire() {
    let (alice, _, bob, group) = fixture().await;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, b"{\"schema\":\"receiver-wire.v1\"}\n").unwrap();
    assert!(matches!(
        ProtectedReceiver::new(bob, group, vec![alice.self_id()], file.reopen().unwrap()),
        Err(ReceiverHold::Configuration)
    ));
}

#[tokio::test]
async fn receiver_oversize_input_refuses_without_latching_or_partial_record() {
    let (mut alice, _, bob, group) = fixture().await;
    let mut wire = send_app(&mut alice, &group, b"approve".to_vec()).await;
    wire.payload = vec![0; 1024 * 1024];
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver =
        ProtectedReceiver::new(bob, group, vec![alice.self_id()], file.reopen().unwrap()).unwrap();
    assert_eq!(
        receiver.ingest(wire).await.unwrap_err(),
        ReceiverHold::Capacity
    );
    let valid = send_app(&mut alice, &receiver.group, b"next valid input".to_vec()).await;
    assert!(receiver.ingest(valid).await.unwrap().is_some());
    assert_eq!(records(&file).len(), 2);
}

#[tokio::test]
async fn receiver_state_change_latches_without_returning_an_approval_candidate() {
    let (mut alice, _, bob, group) = fixture().await;
    let (mut carol, _) = build_client(b"receiver-carol");
    let result = alice
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![carol.fresh_key_package().await.unwrap()],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution {
        msg: mut commit, ..
    } = result
    else {
        panic!("invite evolution")
    };
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver =
        ProtectedReceiver::new(bob, group, vec![alice.self_id()], file.reopen().unwrap()).unwrap();
    assert_eq!(
        receiver.ingest(commit.clone()).await.unwrap_err(),
        ReceiverHold::ChangedState
    );
    assert_eq!(
        receiver.ingest(commit).await.unwrap_err(),
        ReceiverHold::Latched
    );
    assert_eq!(
        records(&file).len(),
        1,
        "original retained; no fabricated completed outcome"
    );
}

#[tokio::test]
async fn receiver_skips_authenticated_nonoperator_malformed_inner_without_latching() {
    let (alice, storage, bob, group) = fixture().await;
    let wire =
        raw_app_message_with_payload(&storage, &alice.self_id(), &group, b"not an inner event");
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver = ProtectedReceiver::new(
        bob,
        group,
        vec![MemberId::new(pad32(b"other"))],
        file.reopen().unwrap(),
    )
    .unwrap();
    assert!(matches!(receiver.ingest(wire).await, Ok(None)));
    assert!(!receiver.latched);
    assert!(records(&file)[1]["candidate"].is_null());
}

#[tokio::test]
async fn receiver_acknowledges_only_after_durable_outcome() {
    use cgka_traits::storage::MessageStorage;
    let (mut alice, _, bob, group) = fixture().await;
    let storage = bob.storage.clone();
    // The fixture deliberately drained its Welcome but never projected/acked it.
    let welcome_ids: Vec<_> = storage
        .list_pending_application_events()
        .unwrap()
        .into_iter()
        .filter_map(|e| {
            if let GroupEvent::GroupJoined { via_welcome, .. } = e {
                Some(via_welcome)
            } else {
                None
            }
        })
        .collect();
    storage
        .delete_pending_application_events(&welcome_ids)
        .unwrap();
    let wire = send_app(&mut alice, &group, b"durable approval".to_vec()).await;
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver =
        ProtectedReceiver::new(bob, group, vec![alice.self_id()], file.reopen().unwrap()).unwrap();
    let candidate = receiver.ingest(wire).await.unwrap().unwrap();
    assert!(
        storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
    let rows = records(&file);
    assert_eq!(rows[1]["candidate"]["message_id"], candidate.message_id);
    assert_eq!(
        rows[1]["pending_application_ids"].as_array().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn receiver_durable_nonoperator_projection_also_acknowledges_plaintext() {
    use cgka_traits::storage::MessageStorage;
    let (mut alice, _, bob, group) = fixture().await;
    let storage = bob.storage.clone();
    let wire = send_app(&mut alice, &group, b"ordinary group chat".to_vec()).await;
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver = ProtectedReceiver::new(
        bob,
        group,
        vec![MemberId::new(pad32(b"not-alice"))],
        file.reopen().unwrap(),
    )
    .unwrap();
    assert!(receiver.ingest(wire).await.unwrap().is_none());
    assert!(
        !storage
            .list_pending_application_events()
            .unwrap()
            .iter()
            .any(|e| matches!(e, GroupEvent::MessageReceived { .. }))
    );
    let rows = records(&file);
    assert!(rows[1]["candidate"].is_null());
    assert_eq!(
        rows[1]["pending_application_ids"].as_array().unwrap().len(),
        1
    );
}
