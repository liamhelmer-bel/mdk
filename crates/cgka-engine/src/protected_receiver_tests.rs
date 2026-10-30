use super::*;
use crate::distributed_convergence::tests::{PassthroughPeeler, TestProofSigner};
use crate::provider::EngineOpenMlsProvider;
use crate::{DEFAULT_CIPHERSUITE, EngineBuilder};
use cgka_traits::MessageStorage;
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
        ReceiverHold::Engine
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

#[tokio::test]
async fn native_merge_capture_refuses_actual_routine_update_convergence() {
    let (mut alice, _, mut bob, group) = fixture().await;
    let result = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution {
        msg: mut commit, ..
    } = result
    else {
        panic!("update commit")
    };
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let content = hash_id(&commit.payload);
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::default());
    assert!(matches!(
        bob.ingest(commit).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    let capture = bob.receiver_merge_capture.as_ref().unwrap();
    assert!(capture.convergence_entered);
    assert!(capture.direct.is_none());
    assert!(!capture.qualifies(&group, &content));
}

#[tokio::test]
async fn native_merge_capture_refuses_actual_roster_change_convergence() {
    let (mut alice, _, mut bob, group) = fixture().await;
    let (mut carol, _) = build_client(b"merge-evidence-carol");
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
        panic!("invite commit")
    };
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let content = hash_id(&commit.payload);
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::default());
    assert!(matches!(
        bob.ingest(commit).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    let capture = bob.receiver_merge_capture.as_ref().unwrap();
    assert!(capture.convergence_entered);
    assert!(!capture.qualifies(&group, &content));
}

#[tokio::test]
async fn native_owned_receiver_direct_update_retains_exact_authenticated_policy() {
    let (mut alice, _, mut bob, group) = fixture().await;
    let before = bob.group_authority(&group).unwrap().facts.epoch;
    let result = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution {
        msg: mut commit, ..
    } = result
    else {
        panic!("update commit")
    };
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let content = hash_id(&commit.payload);
    commit.id = MessageId::new(vec![0x71; 32]);
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(group.clone()));
    let outcome = bob.ingest(commit.clone()).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Processed), "{outcome:?}");
    let capture = bob.receiver_merge_capture.as_ref().unwrap();
    assert!(capture.qualifies(&group, &content), "{capture:?}");
    assert!(!capture.qualifies(&group, &commit.id));
    let evidence = serde_json::to_value(capture.direct.as_ref().unwrap()).unwrap();
    assert_eq!(
        evidence["committer"],
        serde_json::to_value(alice.self_id()).unwrap()
    );
    assert_eq!(
        evidence["before"]["indexed_credentials"],
        evidence["after"]["indexed_credentials"]
    );
    assert_eq!(
        evidence["before"]["extensions"],
        evidence["after"]["extensions"]
    );
    assert_eq!(
        bob.group_authority(&group).unwrap().facts.epoch.0,
        before.0 + 1
    );
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(group.clone()));
    bob.ingest(commit).await.unwrap();
    assert!(
        !bob.receiver_merge_capture
            .as_ref()
            .unwrap()
            .qualifies(&group, &content),
        "duplicate is not another native update"
    );
}

#[tokio::test]
async fn native_owned_receiver_rejects_actual_invite_before_merge() {
    let (mut alice, _, mut bob, group) = fixture().await;
    let before = bob.group_authority(&group).unwrap();
    let (mut carol, _) = build_client(b"owned-receiver-carol");
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
        panic!("invite commit")
    };
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(group.clone()));
    assert!(matches!(
        bob.ingest(commit).await,
        Err(EngineError::Other(_))
    ));
    assert_eq!(bob.group_authority(&group).unwrap(), before);
    assert!(
        bob.receiver_merge_capture
            .as_ref()
            .unwrap()
            .direct
            .is_none()
    );
}

#[tokio::test]
async fn receiver_routine_update_remains_live_and_journals_native_evidence() {
    let (mut alice, _, bob, group) = fixture().await;
    let result = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution {
        msg: mut commit,
        pending,
        ..
    } = result
    else {
        panic!("update commit")
    };
    alice.confirm_published(pending).await.unwrap();
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver = ProtectedReceiver::new(
        bob,
        group.clone(),
        vec![alice.self_id()],
        file.reopen().unwrap(),
    )
    .unwrap();
    assert!(receiver.ingest(commit).await.unwrap().is_none());
    let log = records(&file);
    assert!(!log[1]["native_merge"].is_null());
    assert!(log[1]["candidate"].is_null());
    let reply = send_app(&mut alice, &group, b"approve".to_vec()).await;
    assert!(receiver.ingest(reply).await.unwrap().is_some());
    assert_eq!(records(&file).len(), 4);
}

#[tokio::test]
async fn native_owned_receiver_competing_old_epoch_update_enters_convergence() {
    let (mut alice, _) = build_client(b"race-alice");
    let (mut bob, _) = build_client(b"race-bob");
    let (mut carol, _) = build_client(b"race-carol");
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "receiver race".into(),
            description: String::new(),
            members: vec![
                bob.fresh_key_package().await.unwrap(),
                carol.fresh_key_package().await.unwrap(),
            ],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("group")
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"race-bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"race-carol"))
        .await
        .unwrap();
    bob.drain_events();
    let SendResult::GroupEvolution { msg: mut first, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("first update")
    };
    let SendResult::GroupEvolution { msg: mut rival, .. } = carol
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("rival update")
    };
    for commit in [&mut first, &mut rival] {
        commit.envelope = TransportEnvelope::GroupMessage {
            transport_group_id: group.as_slice().to_vec(),
        };
    }
    let first_content = hash_id(&first.payload);
    let rival_content = hash_id(&rival.payload);
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(group.clone()));
    assert!(matches!(
        bob.ingest(first).await.unwrap(),
        IngestOutcome::Processed
    ));
    assert!(
        bob.receiver_merge_capture
            .as_ref()
            .unwrap()
            .qualifies(&group, &first_content)
    );
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(group.clone()));
    let outcome = bob.ingest(rival).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "{outcome:?}"
    );
    assert!(
        bob.receiver_merge_capture
            .as_ref()
            .unwrap()
            .convergence_entered
    );
    assert!(
        !bob.receiver_merge_capture
            .as_ref()
            .unwrap()
            .qualifies(&group, &rival_content)
    );
}

#[tokio::test]
async fn native_owned_receiver_pending_local_commit_cannot_qualify() {
    let (mut alice, _, mut bob, group) = fixture().await;
    bob.send(SendIntent::SelfUpdate {
        group_id: group.clone(),
    })
    .await
    .unwrap();
    let SendResult::GroupEvolution {
        msg: mut commit, ..
    } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("peer update")
    };
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let content = hash_id(&commit.payload);
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(group.clone()));
    let _outcome = bob.ingest(commit).await;
    assert!(
        !bob.receiver_merge_capture
            .as_ref()
            .unwrap()
            .qualifies(&group, &content)
    );
}

#[tokio::test]
async fn native_owned_receiver_future_epoch_update_cannot_qualify() {
    let (mut alice, _, mut bob, group) = fixture().await;
    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("first update")
    };
    alice.confirm_published(pending).await.unwrap();
    let SendResult::GroupEvolution {
        msg: mut commit, ..
    } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("future update")
    };
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let content = hash_id(&commit.payload);
    bob.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(group.clone()));
    let outcome = bob.ingest(commit).await.unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Buffered { .. }),
        "{outcome:?}"
    );
    assert!(
        !bob.receiver_merge_capture
            .as_ref()
            .unwrap()
            .qualifies(&group, &content)
    );
}

#[tokio::test]
async fn receiver_nonoperator_routine_update_does_not_lock_queue() {
    let (mut alice, _, bob, group) = fixture().await;
    let SendResult::GroupEvolution {
        msg: mut commit,
        pending,
        ..
    } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("update commit")
    };
    alice.confirm_published(pending).await.unwrap();
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut receiver = ProtectedReceiver::new(
        bob,
        group.clone(),
        vec![MemberId::new(pad32(b"other-operator"))],
        file.reopen().unwrap(),
    )
    .unwrap();
    assert!(receiver.ingest(commit).await.unwrap().is_none());
    assert!(!records(&file)[1]["native_merge"].is_null());
    let ordinary = send_app(&mut alice, &group, b"hello".to_vec()).await;
    assert!(receiver.ingest(ordinary).await.unwrap().is_none());
    assert!(!receiver.latched);
}

#[cfg(unix)]
pub(super) fn ordered_fixture(
    root: &std::path::Path,
    engine: &Engine<SqliteAccountStorage>,
    group: &GroupId,
    operators: &[MemberId],
) -> (
    crate::protected_recovery::Journal,
    crate::protected_recovery::Enrollment,
) {
    use crate::protected_recovery::{Enrollment, Journal, OwnedFiles};
    use std::{
        fs::{File, OpenOptions},
        os::unix::fs::OpenOptionsExt,
    };
    let receiver = root.join("receiver");
    let consumer = root.join("consumer");
    std::fs::create_dir_all(&receiver).unwrap();
    std::fs::create_dir_all(&consumer).unwrap();
    let open = |p| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(p)
            .unwrap()
    };
    let projection = engine
        .with_mls_group(group, crate::protected_merge::Projection::read)
        .unwrap();
    let enrollment = Enrollment {
        account: hex::encode(engine.self_id().as_slice()),
        group: hex::encode(group.as_slice()),
        operators: operators
            .iter()
            .map(|m| hex::encode(m.as_slice()))
            .collect(),
        // Synthetic installation and welcome pins: these tests qualify actual
        // native/journal mechanics, not a production enrollment or custody.
        source_profile_sha256: "55".repeat(32),
        storage_generation: "66".repeat(32),
        initial_native_state_sha256: hex::encode(Sha256::digest(
            serde_json::to_vec(&projection).unwrap(),
        )),
        welcome_provenance_sha256: "88".repeat(32),
    };
    let journal = Journal::enroll(
        OwnedFiles {
            journal: open(receiver.join("journal")),
            journal_directory: File::open(&receiver).unwrap(),
            storage_lease: open(receiver.join("storage-lease")),
            anchor: open(consumer.join("anchor")),
            anchor_directory: File::open(&consumer).unwrap(),
        },
        enrollment.clone(),
    )
    .unwrap();
    (journal, enrollment)
}

#[cfg(unix)]
fn ordered_sources(root: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(root.join("receiver/journal"))
        .unwrap()
        .lines()
        .filter_map(|line| {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            record["body"]["payload_hex"]
                .as_str()
                .map(|payload| serde_json::from_slice(&hex::decode(payload).unwrap()).unwrap())
        })
        .collect()
}

#[cfg(unix)]
#[tokio::test]
async fn ordered_actual_native_ingest_anchors_projection_before_positive_plaintext_ack() {
    let (mut alice, _, bob, group) = fixture().await;
    let storage = bob.storage.clone();
    let wire = send_app(&mut alice, &group, b"original MLS application".to_vec()).await;
    let root = tempfile::tempdir().unwrap();
    let operators = vec![alice.self_id()];
    let (journal, _) = ordered_fixture(root.path(), &bob, &group, &operators);
    let mut receiver =
        ProtectedReceiver::from_ordered(bob, group.clone(), operators, journal).unwrap();
    let candidate = receiver.ingest(wire.clone()).await.unwrap().unwrap();
    let sources = ordered_sources(root.path());
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0]["schema"], "receiver-wire.v1");
    assert_eq!(sources[0]["wire"], serde_json::to_value(wire).unwrap());
    let outcome = &sources[1];
    let projection = &outcome["pending_application_projections"][0];
    assert_eq!(projection["group"], serde_json::to_value(group).unwrap());
    assert_eq!(
        projection["sender"],
        serde_json::to_value(alice.self_id()).unwrap()
    );
    assert_eq!(projection["source_epoch"], candidate.source_epoch);
    assert_eq!(outcome["candidate"]["message_id"], candidate.message_id);
    assert_eq!(
        projection["message_id"],
        outcome["pending_application_ids"][0]
    );
    assert!(projection["payload_sha256"].as_str().unwrap().len() == 64);
    let pending = storage.list_pending_application_events().unwrap();
    // The earlier native welcome remains pending: this source slice never
    // silently acknowledges unrelated state events as application projections.
    assert!(!pending.is_empty());
    assert!(
        pending
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
    let journal_count = std::fs::read_to_string(root.path().join("receiver/journal"))
        .unwrap()
        .lines()
        .count();
    let anchor_count = std::fs::read_to_string(root.path().join("consumer/anchor"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(journal_count, 3);
    assert_eq!(anchor_count, journal_count);
}

#[cfg(unix)]
#[tokio::test]
async fn ordered_nonoperator_has_exact_pending_projection_without_approval_candidate() {
    let (mut alice, _, bob, group) = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let operators = vec![MemberId::new(pad32(b"unrelated-operator"))];
    let (journal, _) = ordered_fixture(root.path(), &bob, &group, &operators);
    let mut receiver =
        ProtectedReceiver::from_ordered(bob, group.clone(), operators, journal).unwrap();
    let wire = send_app(&mut alice, &group, b"normal member content".to_vec()).await;
    assert!(receiver.ingest(wire).await.unwrap().is_none());
    let sources = ordered_sources(root.path());
    assert!(sources[1]["candidate"].is_null());
    assert_eq!(
        sources[1]["pending_application_projections"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        sources[1]["pending_application_projections"][0]["sender"],
        serde_json::to_value(alice.self_id()).unwrap()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ordered_constructor_refuses_native_state_not_matching_owned_header() {
    let (alice, _, bob, group) = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let operators = vec![alice.self_id()];
    let (journal, _) = ordered_fixture(root.path(), &bob, &group, &operators);
    let wrong = vec![MemberId::new(pad32(b"different-operator"))];
    assert!(matches!(
        ProtectedReceiver::from_ordered(bob, group, wrong, journal),
        Err(ReceiverHold::Configuration)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn ordered_reconcile_requires_exact_actual_pending_tuple_and_complete_wire_outcome() {
    for mode in 0..4 {
        let (mut alice, _, mut bob, group) = fixture().await;
        let storage = bob.storage.clone();
        // Explicit fixture enrollment consumes its actual earlier welcome. This
        // test does not qualify the production welcome-provenance factory.
        let welcome = storage
            .list_pending_application_events()
            .unwrap()
            .into_iter()
            .find(|e| matches!(e, GroupEvent::GroupJoined { .. }))
            .unwrap();
        let welcome_ids = storage
            .list_pending_application_events()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                GroupEvent::GroupJoined { via_welcome, .. } => Some(via_welcome.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        storage
            .delete_pending_application_events(&welcome_ids)
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let operators = vec![alice.self_id()];
        let (mut journal, _) = ordered_fixture(root.path(), &bob, &group, &operators);
        let wire = send_app(&mut alice, &group, b"durable pending".to_vec()).await;
        let outcome = bob.ingest(wire.clone()).await.unwrap();
        bob.drain_events();
        let pending = storage.list_pending_application_events().unwrap();
        assert_eq!(pending.len(), 1);
        let actual = PendingApplicationProjection::capture(&pending[0]).unwrap();
        journal
            .record_source(
                serde_json::json!({"schema":"receiver-wire.v1", "sequence":1,
            "received_at_unix_ms":1, "wire":wire}),
            )
            .unwrap();
        if mode != 2 {
            let mut retained = serde_json::to_value(&actual).unwrap();
            if mode == 1 {
                retained["payload_sha256"] = serde_json::Value::String("aa".repeat(32));
            }
            journal.record_source(serde_json::json!({"schema":"receiver-outcome.v1", "sequence":1,
                "message_id":hex::encode(wire.id.as_slice()),"outcome":outcome,"candidate":null,
                "pending_application_ids":[actual.message_id],"pending_application_projections":[retained],"native_merge":null})).unwrap();
        }
        if mode == 3 {
            // A real pending Welcome alongside a matching application refuses
            // the entire acknowledgment, preserving even the matched output.
            storage.put_pending_application_event(&welcome).unwrap();
        }
        let result = ProtectedReceiver::reconcile_pending_plaintext(&mut bob, &journal);
        if mode == 0 {
            result.unwrap();
            assert!(
                storage
                    .list_pending_application_events()
                    .unwrap()
                    .is_empty()
            );
            // Repeated positive acknowledgment is harmless, never a wire replay.
            ProtectedReceiver::reconcile_pending_plaintext(&mut bob, &journal).unwrap();
        } else {
            assert_eq!(result, Err(ReceiverHold::ChangedState));
            assert!(
                storage
                    .list_pending_application_events()
                    .unwrap()
                    .iter()
                    .any(
                        |event| PendingApplicationProjection::capture(event).as_ref()
                            == Some(&actual)
                    )
            );
        }
    }
}
