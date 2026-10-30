use super::*;
use crate::distributed_convergence::tests::{PassthroughPeeler, TestProofSigner};
use cgka_traits::{GroupStorage, MessageStorage};
fn build_client(
    seed: &[u8],
) -> (
    Engine<storage_sqlite::SqliteAccountStorage>,
    storage_sqlite::SqliteAccountStorage,
) {
    let key = (0u64..)
        .find_map(|i| {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(i.to_be_bytes());
            k256::schnorr::SigningKey::from_bytes(&h.finalize()).ok()
        })
        .unwrap();
    let storage = storage_sqlite::SqliteAccountStorage::in_memory().unwrap();
    let engine = crate::EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(key.verifying_key().to_bytes().to_vec())
        .account_identity_proof_signer(std::sync::Arc::new(TestProofSigner(key)))
        .peeler(Box::new(PassthroughPeeler))
        .build()
        .unwrap();
    (engine, storage)
}
use cgka_traits::engine::{CreateGroupRequest, SendResult};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

fn intent(root: &std::path::Path) -> JoinIntent {
    JoinIntent {
        file: OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(root.join("join-intent"))
            .unwrap(),
        directory: File::open(root).unwrap(),
    }
}
async fn invitation() -> (
    Engine<storage_sqlite::SqliteAccountStorage>,
    storage_sqlite::SqliteAccountStorage,
    TransportMessage,
    GroupId,
    MemberId,
) {
    let (mut inviter, _) = build_client(b"owned-join-inviter");
    let (mut recipient, storage) = build_client(b"owned-join-recipient");
    let (group, sent) = inviter
        .create_group(CreateGroupRequest {
            name: "owned-join".into(),
            description: String::new(),
            members: vec![recipient.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = sent
    else {
        panic!("fixture")
    };
    inviter.confirm_published(pending).await.unwrap();
    recipient.drain_events();
    (
        recipient,
        storage,
        welcomes.remove(0),
        group,
        inviter.self_id(),
    )
}
#[tokio::test]
async fn live_join_captures_original_and_native_identity_without_acknowledging() {
    let (mut recipient, storage, mut wire, group, inviter) = invitation().await;
    wire.id = MessageId::new(vec![0x73; 32]);
    let root = tempfile::tempdir().unwrap();
    let evidence = recipient
        .receiver_join_owned(wire.clone(), intent(root.path()))
        .await
        .unwrap();
    assert_eq!(evidence.group, group);
    assert_eq!(evidence.authenticated_welcomer, inviter);
    assert_eq!(evidence.original_wire.id, wire.id);
    assert_ne!(evidence.canonical_content, wire.id);
    let original = serde_json::to_vec(&wire).unwrap();
    assert_eq!(
        std::fs::read(root.path().join("join-intent")).unwrap(),
        original
    );
    assert_eq!(
        evidence.original_wire_sha256,
        hex::encode(Sha256::digest(original))
    );
    let pending = storage.list_pending_application_events().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(evidence.matches_pending(&pending[0]));
    assert_eq!(evidence.digest().unwrap(), evidence.digest().unwrap());
    assert_eq!(recipient.storage.list_groups().unwrap(), vec![group]);
}
#[tokio::test]
async fn failed_native_join_keeps_original_and_cannot_reuse_nonempty_intent() {
    let (mut recipient, storage, mut wire, _, _) = invitation().await;
    wire.payload = vec![0xff; 13];
    let root = tempfile::tempdir().unwrap();
    assert!(
        recipient
            .receiver_join_owned(wire.clone(), intent(root.path()))
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(root.path().join("join-intent")).unwrap(),
        serde_json::to_vec(&wire).unwrap()
    );
    assert!(storage.list_groups().unwrap().is_empty());
    assert!(
        storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
    assert!(recipient.receiver_join_capture.is_none());
    let same = JoinIntent {
        file: OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.path().join("join-intent"))
            .unwrap(),
        directory: File::open(root.path()).unwrap(),
    };
    assert!(recipient.receiver_join_owned(wire, same).await.is_err());
}
#[tokio::test]
async fn historical_join_cannot_be_promoted_to_fresh_provenance() {
    let (mut recipient, _, wire, _, _) = invitation().await;
    recipient.join_welcome(wire.clone()).await.unwrap();
    recipient.drain_events();
    let root = tempfile::tempdir().unwrap();
    assert!(
        recipient
            .receiver_join_owned(wire, intent(root.path()))
            .await
            .is_err()
    );
    assert!(
        std::fs::read(root.path().join("join-intent"))
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn intent_permissions_are_checked_before_consuming_welcome() {
    use std::os::unix::fs::PermissionsExt;
    let (mut recipient, storage, wire, _, _) = invitation().await;
    let root = tempfile::tempdir().unwrap();
    let intent = intent(root.path());
    intent
        .file
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .unwrap();
    assert!(recipient.receiver_join_owned(wire, intent).await.is_err());
    assert!(storage.list_groups().unwrap().is_empty());
    assert!(
        std::fs::read(root.path().join("join-intent"))
            .unwrap()
            .is_empty()
    );
}

fn recovery_files(root: &std::path::Path) -> crate::protected_recovery::OwnedFiles {
    let receiver = root.join("receiver");
    let consumer = root.join("consumer");
    std::fs::create_dir_all(&receiver).unwrap();
    std::fs::create_dir_all(&consumer).unwrap();
    let file = |p| {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(p)
            .unwrap()
    };
    crate::protected_recovery::OwnedFiles {
        journal: file(receiver.join("journal")),
        journal_directory: File::open(&receiver).unwrap(),
        storage_lease: file(receiver.join("storage-lease")),
        anchor: file(consumer.join("anchor")),
        anchor_directory: File::open(&consumer).unwrap(),
    }
}
#[tokio::test]
async fn native_welcome_is_acked_only_after_original_join_is_in_anchored_chain() {
    let (mut recipient, storage, wire, group, inviter) = invitation().await;
    let root = tempfile::tempdir().unwrap();
    let evidence = recipient
        .receiver_join_owned(wire.clone(), intent(root.path()))
        .await
        .unwrap();
    let enrollment = crate::protected_recovery::Enrollment {
        account: hex::encode(recipient.self_id().as_slice()),
        group: hex::encode(group.as_slice()),
        operators: vec![hex::encode(inviter.as_slice())],
        source_profile_sha256: "55".repeat(32),
        storage_generation: "66".repeat(32),
        initial_native_state_sha256: hex::encode(Sha256::digest(
            serde_json::to_vec(&evidence.joined).unwrap(),
        )),
        welcome_provenance_sha256: evidence.digest().unwrap(),
    }; // Synthetic profile/storage pins only: this fixture does not establish custody.
    let journal =
        crate::protected_recovery::Journal::enroll(recovery_files(root.path()), enrollment.clone())
            .unwrap();
    assert_eq!(storage.list_pending_application_events().unwrap().len(), 1);
    let receiver = crate::protected_receiver::ProtectedReceiver::from_native_join(
        recipient,
        group,
        vec![inviter],
        journal,
        evidence,
    )
    .unwrap();
    assert!(
        storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
    let text = std::fs::read_to_string(root.path().join("receiver/journal")).unwrap();
    let values: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(values.len(), 2);
    let payload: serde_json::Value = serde_json::from_slice(
        &hex::decode(values[1]["body"]["payload_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["schema"], "receiver-enrollment.v1");
    assert_eq!(
        payload["native_join"]["original_wire"],
        serde_json::to_value(wire).unwrap()
    );
    drop(receiver);
    assert!(
        crate::protected_recovery::Journal::reopen(recovery_files(root.path()), &enrollment)
            .is_ok()
    );
}
#[tokio::test]
async fn wrong_join_provenance_pin_preserves_actual_native_pending_welcome() {
    let (mut recipient, storage, wire, group, inviter) = invitation().await;
    let root = tempfile::tempdir().unwrap();
    let evidence = recipient
        .receiver_join_owned(wire, intent(root.path()))
        .await
        .unwrap();
    let enrollment = crate::protected_recovery::Enrollment {
        account: hex::encode(recipient.self_id().as_slice()),
        group: hex::encode(group.as_slice()),
        operators: vec![hex::encode(inviter.as_slice())],
        source_profile_sha256: "55".repeat(32),
        storage_generation: "66".repeat(32),
        initial_native_state_sha256: hex::encode(Sha256::digest(
            serde_json::to_vec(&evidence.joined).unwrap(),
        )),
        welcome_provenance_sha256: "88".repeat(32),
    };
    let journal =
        crate::protected_recovery::Journal::enroll(recovery_files(root.path()), enrollment)
            .unwrap();
    assert!(
        crate::protected_receiver::ProtectedReceiver::from_native_join(
            recipient,
            group,
            vec![inviter],
            journal,
            evidence
        )
        .is_err()
    );
    assert_eq!(storage.list_pending_application_events().unwrap().len(), 1);
    assert_eq!(
        std::fs::read_to_string(root.path().join("receiver/journal"))
            .unwrap()
            .lines()
            .count(),
        1
    );
}

#[tokio::test]
async fn failed_postcommit_capture_still_finalizes_actual_native_join() {
    let (mut recipient, storage, wire, group, _) = invitation().await;
    let mut wrong_wire = wire.clone();
    wrong_wire.id = MessageId::new(vec![0x19; 32]);
    recipient.receiver_join_capture = Some(Capture {
        wire: wrong_wire,
        wire_sha256: "00".repeat(32),
        evidence: None,
        failed: false,
    });
    // Deliberately invalid capture fails only after the actual join commits.
    recipient.join_welcome(wire).await.unwrap();
    let capture = recipient.receiver_join_capture.take().unwrap();
    assert!(capture.failed);
    assert!(capture.evidence.is_none());
    assert_eq!(storage.list_groups().unwrap(), vec![group.clone()]);
    assert!(recipient.group_authority(&group).is_ok());
    assert_eq!(storage.list_pending_application_events().unwrap().len(), 1);
    assert!(!recipient.drain_events().is_empty());
}
