use super::*;
use crate::distributed_convergence::tests::{PassthroughPeeler, TestProofSigner};
use cgka_traits::{GroupStorage, MessageStorage};
fn build_client(
    seed: &[u8],
) -> (
    Engine<storage_sqlite::SqliteAccountStorage>,
    storage_sqlite::SqliteAccountStorage,
) {
    let key = fixture_key(seed);
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
fn fixture_key(seed: &[u8]) -> k256::schnorr::SigningKey {
    (0u64..)
        .find_map(|i| {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(i.to_be_bytes());
            k256::schnorr::SigningKey::from_bytes(&h.finalize()).ok()
        })
        .unwrap()
}
use cgka_traits::engine::{CreateGroupRequest, SendResult};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

pub(crate) fn intent(root: &std::path::Path) -> JoinIntent {
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
pub(crate) async fn invitation() -> (
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
    let mut actual_intent = intent(root.path());
    // The inherited file description's cursor is not authority. Retain exact
    // original bytes at offset zero even if its publisher left a stale cursor.
    std::io::Seek::seek(&mut actual_intent.file, std::io::SeekFrom::Start(123)).unwrap();
    let evidence = recipient
        .receiver_join_owned(wire.clone(), actual_intent)
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
async fn rejected_native_welcome_does_not_burn_intent() {
    let (mut recipient, storage, mut wire, _, _) = invitation().await;
    wire.payload = vec![0xff; 13];
    let root = tempfile::tempdir().unwrap();
    assert!(
        recipient
            .receiver_join_owned(wire.clone(), intent(root.path()))
            .await
            .is_err()
    );
    assert!(
        std::fs::read(root.path().join("join-intent"))
            .unwrap()
            .is_empty()
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

pub(crate) fn recovery_files(root: &std::path::Path) -> crate::protected_recovery::OwnedFiles {
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
        schema: "heterodyne-receiver-enrollment.v2".into(),
        expiry_profile_sha256: "66".repeat(32),
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
        schema: "heterodyne-receiver-enrollment.v2".into(),
        expiry_profile_sha256: "66".repeat(32),
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
    let root = tempfile::tempdir().unwrap();
    recipient.receiver_join_capture = Some(Capture {
        wire: wrong_wire,
        wire_sha256: "00".repeat(32),
        evidence: None,
        failed: false,
        intent: intent(root.path()),
        intent_attempted: false,
        constraint: None,
        policy_rejected: false,
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

#[tokio::test]
async fn enrolled_group_operator_and_keypackage_are_checked_before_durable_intent() {
    for wrong in ["group", "operator", "keypackage", "malformed"] {
        let (mut recipient, storage, wire, group, operator) = invitation().await;
        let root = tempfile::tempdir().unwrap();
        let original = intent(root.path());
        let retained = || JoinIntent {
            file: original.file.try_clone().unwrap(),
            directory: original.directory.try_clone().unwrap(),
        };
        let expected = || JoinConstraint {
            template: crate::protected_capability_policy::routing_only_v1(),
            group: group.clone(),
            operators: vec![operator.clone()],
            key_package_ref: hex::decode(key_package_ref(&wire)).unwrap(),
        };
        let mut constraint = expected();
        let mut candidate = wire.clone();
        match wrong {
            "group" => constraint.group = GroupId::new(vec![77; 16]),
            "operator" => constraint.operators = vec![MemberId::new(vec![88; 32])],
            "keypackage" => constraint.key_package_ref = vec![99; 32],
            _ => {
                candidate.payload = vec![0xff; 13];
                candidate.id = MessageId::new(vec![0x41; 32]);
            }
        }
        assert!(
            recipient
                .receiver_join_enrolled(candidate, retained(), constraint)
                .await
                .unwrap()
                .is_none(),
            "{wrong}"
        );
        assert_eq!(original.file.metadata().unwrap().len(), 0, "{wrong}");
        assert!(storage.list_groups().unwrap().is_empty(), "{wrong}");
        assert!(
            storage
                .list_pending_application_events()
                .unwrap()
                .is_empty(),
            "{wrong}"
        );
        // Identical actual Welcome still works: rollback restored the consumed
        // KeyPackage, and no unauthenticated/foreign input spent the intent.
        let joined = recipient
            .receiver_join_enrolled(wire.clone(), retained(), expected())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(joined.group, group);
        assert_eq!(storage.list_pending_application_events().unwrap().len(), 1);
        assert_eq!(
            std::fs::read(root.path().join("join-intent")).unwrap(),
            serde_json::to_vec(&wire).unwrap()
        );
    }
}

#[tokio::test]
async fn intent_io_failure_rolls_back_native_join_but_preserves_unknown() {
    let (mut recipient, storage, wire, group, operator) = invitation().await;
    let root = tempfile::tempdir().unwrap();
    let original = intent(root.path());
    let read_only = JoinIntent {
        file: File::open(root.path().join("join-intent")).unwrap(),
        directory: original.directory.try_clone().unwrap(),
    };
    let result = recipient
        .receiver_join_enrolled(
            wire.clone(),
            read_only,
            JoinConstraint {
                template: crate::protected_capability_policy::routing_only_v1(),
                group,
                operators: vec![operator],
                key_package_ref: hex::decode(key_package_ref(&wire)).unwrap(),
            },
        )
        .await;
    assert!(matches!(result, Err(EngineError::Backend(_))));
    assert!(storage.list_groups().unwrap().is_empty());
    assert!(
        storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
    // Empty bytes do not imply safe retry: write was actually attempted, so
    // the owning entry treats this typed error as reconciliation-only HOLD.
    assert_eq!(original.file.metadata().unwrap().len(), 0);
}

#[tokio::test]
async fn forged_nip59_giftwrap_does_not_spend_real_welcome_attempt() {
    use cgka_traits::peeler::TransportPeeler;
    use cgka_traits::transport::EncryptedPayload;
    use transport_nostr_peeler::NostrMlsPeeler;
    let (mut recipient, storage, raw, group, operator) = invitation().await;
    let sender = nostr::Keys::new(
        nostr::SecretKey::from_slice(&fixture_key(b"owned-join-inviter").to_bytes()).unwrap(),
    );
    let receiver = nostr::Keys::new(
        nostr::SecretKey::from_slice(&fixture_key(b"owned-join-recipient").to_bytes()).unwrap(),
    );
    assert_eq!(
        receiver.public_key().to_bytes().as_slice(),
        recipient.self_id().as_slice()
    );
    recipient.peeler = Box::new(NostrMlsPeeler::new().with_welcome_signer(receiver));
    let valid = NostrMlsPeeler::new()
        .with_welcome_signer(sender)
        .wrap_welcome_with_metadata(
            &EncryptedPayload {
                ciphertext: raw.payload.clone(),
                aad: vec![],
            },
            &recipient.self_id(),
            &cgka_traits::engine::WelcomeMetadata {
                key_package_event_id: MessageId::new(vec![44; 32]),
                relays: vec![cgka_traits::TransportEndpoint(
                    "wss://fixture.invalid".into(),
                )],
            },
        )
        .await
        .unwrap();
    let mut forged = valid.clone();
    let mut event: serde_json::Value = serde_json::from_slice(&valid.payload).unwrap();
    event["sig"] = serde_json::json!("00".repeat(64));
    forged.payload = serde_json::to_vec(&event).unwrap();
    let root = tempfile::tempdir().unwrap();
    let original = intent(root.path());
    let retained = || JoinIntent {
        file: original.file.try_clone().unwrap(),
        directory: original.directory.try_clone().unwrap(),
    };
    let expected = || JoinConstraint {
        template: crate::protected_capability_policy::routing_only_v1(),
        group: group.clone(),
        operators: vec![operator.clone()],
        key_package_ref: hex::decode(key_package_ref(&raw)).unwrap(),
    };
    assert!(
        recipient
            .receiver_join_enrolled(forged, retained(), expected())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(original.file.metadata().unwrap().len(), 0);
    assert!(storage.list_groups().unwrap().is_empty());
    let evidence = recipient
        .receiver_join_enrolled(valid.clone(), retained(), expected())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence.group, group);
    assert_eq!(evidence.authenticated_welcomer, operator);
    assert_eq!(
        std::fs::read(root.path().join("join-intent")).unwrap(),
        serde_json::to_vec(&valid).unwrap()
    );
    assert_eq!(storage.list_pending_application_events().unwrap().len(), 1);
}

/// Test fixture only: recover the actual native KeyPackageRef in this raw MLS
/// Welcome. The production profile is retained by the enrollment publisher.
pub(crate) fn key_package_ref(wire: &TransportMessage) -> String {
    use tls_codec::Deserialize;
    let message =
        openmls::prelude::MlsMessageIn::tls_deserialize_exact(wire.payload.as_slice()).unwrap();
    let openmls::prelude::MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        panic!("welcome")
    };
    hex::encode(welcome.secrets()[0].new_member().as_slice())
}

#[tokio::test]
async fn oversized_preintent_input_is_rejected_then_real_welcome_joins() {
    let (mut engine, storage, wire, _, _) = invitation().await;
    let root = tempfile::tempdir().unwrap();
    let intent = intent(root.path());
    let mut oversized = wire.clone();
    oversized.payload = vec![255; 400_000];
    assert!(
        engine
            .receiver_join_attempt(
                oversized,
                JoinIntent {
                    file: intent.file.try_clone().unwrap(),
                    directory: intent.directory.try_clone().unwrap(),
                },
                None
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(storage.list_groups().unwrap().is_empty());
    assert_eq!(intent.file.metadata().unwrap().len(), 0);
    assert!(engine.receiver_join_owned(wire, intent).await.is_ok());
}
