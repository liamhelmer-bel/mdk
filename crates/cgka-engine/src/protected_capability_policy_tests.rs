use super::*;
use crate::Engine;
use crate::protected_capability_policy::{
    Template, admind_receiver_v1, bounded_app_receiver_v1, routing_only_v1,
};
use crate::protected_join::{JoinConstraint, JoinIntent};
use cgka_traits::{
    engine::{CgkaEngine, CreateGroupRequest, SendResult},
    storage::{GroupStorage, MessageStorage},
};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

fn client(template: Template) -> Engine<SqliteAccountStorage> {
    let keys = nostr::Keys::generate();
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .supported_app_components(template.components())
        .feature_registry(template.registry())
        .identity(keys.public_key().to_bytes().to_vec())
        .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
        .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(keys)))
        .build()
        .unwrap()
}
#[tokio::test]
async fn closed_templates_match_actual_persisted_private_package_metadata() {
    for template in [
        routing_only_v1(),
        bounded_app_receiver_v1(),
        admind_receiver_v1(),
    ] {
        let mut engine = if template == routing_only_v1() {
            owned_routed_engine(
                SqliteAccountStorage::in_memory().unwrap(),
                nostr::Keys::generate(),
                routing_only_v1(),
            )
            .unwrap()
        } else {
            client(template)
        };
        let kp = engine.fresh_key_package().await.unwrap();
        let actual = crate::key_package_metadata(&kp).unwrap();
        template.validate_metadata(&actual).unwrap();
        let retained = crate::key_package::durably_owned_key_packages(
            &engine.storage,
            cgka_traits::group::ProtocolProfile::Current,
        )
        .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(crate::key_package_metadata(&retained[0]).unwrap(), actual);
        for field in [
            "extension",
            "proposal",
            "component",
            "profile",
            "ciphersuite",
        ] {
            let mut wrong = actual.clone();
            match field {
                "extension" => wrong.mls_extensions.push(0xf2d2),
                "proposal" => wrong.mls_proposals.push(10),
                "component" => wrong.app_components.push(0x8005),
                "profile" => wrong.protocol_profile = cgka_traits::group::ProtocolProfile::Legacy,
                _ => wrong.ciphersuite = 2,
            }
            assert!(template.validate_metadata(&wrong).is_err(), "{field}");
        }
    }
}
#[tokio::test]
async fn rollbackable_bounded_policy_refuses_native_valid_wider_values_without_spending_package() {
    for template in [bounded_app_receiver_v1(), admind_receiver_v1()] {
        rollbackable_policy_cases(template).await;
    }
}
async fn rollbackable_policy_cases(template: Template) {
    use cgka_traits::agent_text_stream::AgentTextStreamQuicPolicyV1;
    use cgka_traits::app_components::{
        AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
    };
    for variant in [
        "bounded",
        "frame8192",
        "fanout",
        "replay",
        "padding",
        "optional-unknown",
    ] {
        let mut inviter = if variant == "optional-unknown" {
            let keys = nostr::Keys::generate();
            let mut components = template.components();
            components.insert(0x9000);
            EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
                .supported_app_components(components)
                .feature_registry(template.registry())
                .identity(keys.public_key().to_bytes().to_vec())
                .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
                .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(keys)))
                .build()
                .unwrap()
        } else {
            client(template)
        };
        let mut recipient = client(template);
        let mut native_control = client(template);
        let mut replay_control = client(template);
        let mut replay_kp = replay_control.fresh_key_package().await.unwrap();
        replay_kp.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::types::MessageId::new(vec![6; 32]),
        });
        let mut control_kp = native_control.fresh_key_package().await.unwrap();
        control_kp.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::types::MessageId::new(vec![5; 32]),
        });
        let mut kp = recipient.fresh_key_package().await.unwrap();
        let reference = hex::decode(
            crate::key_package_metadata(&kp)
                .unwrap()
                .key_package_ref_hex,
        )
        .unwrap();
        kp.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::types::MessageId::new(vec![4; 32]),
        });
        let mut policy = AgentTextStreamQuicPolicyV1::user_to_agent_default();
        match variant {
            "frame8192" => policy.max_plaintext_frame_len = 8192,
            "fanout" => policy.allowed_member_roles = 7,
            "replay" => policy.replay_ttl_secs = 1,
            "padding" => policy.padding_bucket_bytes = 16,
            _ => {}
        }
        let (group, sent) = inviter
            .create_group_with_optional_app_components(
                CreateGroupRequest {
                    name: "bounded handling fixture".into(),
                    description: String::new(),
                    members: vec![kp, control_kp, replay_kp],
                    required_features: vec![],
                    initial_admins: vec![],
                    app_components: vec![
                    AppComponentData {
                        component_id: NOSTR_ROUTING_COMPONENT_ID,
                        data: encode_nostr_routing_v1(
                            &NostrRoutingV1::new([7; 32], vec!["wss://bounded.invalid".into()])
                                .unwrap(),
                        )
                        .unwrap(),
                    },
                    policy.to_app_component_data().unwrap(),
                    AppComponentData {
                        component_id:
                            cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
                        data: cgka_traits::app_components::encode_encrypted_media_policy_v2(
                            &cgka_traits::app_components::EncryptedMediaPolicyV2::blossom_default(
                                vec!["https://media.invalid".into()],
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    },
                ],
                },
                if variant == "optional-unknown" {
                    vec![AppComponentData {
                        component_id: 0x9000,
                        data: vec![0x41],
                    }]
                } else {
                    vec![]
                },
            )
            .await
            .unwrap();
        let SendResult::FoundingGroupCreated { mut welcomes } = sent else {
            panic!("Current founding group")
        };
        let position=welcomes.iter().position(|w|matches!(&w.envelope,cgka_traits::TransportEnvelope::Welcome{recipient:r} if r==&recipient.self_id())).unwrap();
        let wire = welcomes.remove(position);
        let position = welcomes.iter().position(|w| matches!(&w.envelope, cgka_traits::TransportEnvelope::Welcome { recipient:r } if r == &native_control.self_id())).unwrap();
        let control_wire = welcomes.remove(position);
        let replay_wire = welcomes.remove(0);
        let root = tempfile::tempdir().unwrap();
        let original = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(root.path().join("intent"))
            .unwrap();
        let constraint = |template| JoinConstraint {
            group: group.clone(),
            expected_welcomer: inviter.self_id(),
            operators: vec![inviter.self_id()],
            key_package_ref: reference.clone(),
            template,
        };
        let intent = || JoinIntent {
            file: original.try_clone().unwrap(),
            directory: File::open(root.path()).unwrap(),
        };
        let result = recipient
            .receiver_join_enrolled(wire.clone(), intent(), constraint(template))
            .await
            .unwrap();
        if variant == "bounded" {
            let control_intent = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(root.path().join("control-intent"))
                .unwrap();
            native_control
                .receiver_join_owned(
                    control_wire,
                    JoinIntent {
                        file: control_intent,
                        directory: File::open(root.path()).unwrap(),
                    },
                )
                .await
                .unwrap();
            native_control.drain_events();
            let replay_intent = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(root.path().join("replay-intent"))
                .unwrap();
            replay_control
                .receiver_join_owned(
                    replay_wire,
                    JoinIntent {
                        file: replay_intent,
                        directory: File::open(root.path()).unwrap(),
                    },
                )
                .await
                .unwrap();
            replay_control.drain_events();
            assert!(result.is_some());
            assert_eq!(
                recipient.storage.list_groups().unwrap(),
                vec![group.clone()]
            );
            // Lower native functional receive path: transient start is harmless
            // and the durable final remains an ordinary chat event. No QUIC or
            // media URL is opened, and no approval is created by this fixture.
            recipient.drain_events();
            let journal = tempfile::NamedTempFile::new().unwrap();
            let mut receiver = ProtectedReceiver::new(
                recipient,
                group.clone(),
                vec![inviter.self_id()],
                journal.reopen().unwrap(),
            )
            .unwrap();
            let mut start_id = String::new();
            for kind in [1200, 9] {
                let tags = if kind == 1200 {
                    vec![
                        vec!["stream".into(), "01".repeat(32)],
                        vec!["stream-type".into(), "text".into()],
                        vec!["final-kind".into(), "9".into()],
                        vec!["route".into(), "quic".into()],
                        vec!["broker".into(), "quic://preview.invalid:443".into()],
                    ]
                } else {
                    vec![
                        vec!["stream".into(), "01".repeat(32)],
                        vec!["stream-start".into(), start_id.clone()],
                        vec!["stream-hash".into(), "00".repeat(32)],
                        vec!["stream-chunks".into(), "0".into()],
                    ]
                };
                let app = cgka_traits::app_event::MarmotAppEvent::new(
                    hex::encode(inviter.self_id().as_slice()),
                    1,
                    kind,
                    tags,
                    if kind == 1200 {
                        r#"{"preview":"!answer ask4 yes"}"#
                    } else {
                        "durable final text"
                    },
                );
                let payload = app.encode().unwrap();
                if kind == 1200 {
                    start_id = serde_json::from_slice::<serde_json::Value>(&payload).unwrap()["id"]
                        .as_str()
                        .unwrap()
                        .into();
                }
                let SendResult::ApplicationMessage { msg, .. } = inviter
                    .send(cgka_traits::engine::SendIntent::AppMessage {
                        group_id: group.clone(),
                        payload,
                        expected_epoch: None,
                    })
                    .await
                    .unwrap()
                else {
                    panic!("native application")
                };
                let candidate = receiver.ingest(msg).await.unwrap();
                assert_eq!(candidate.is_some(), kind == 9);
                assert!(
                    candidate.is_none_or(|c| c.application.kind == 9
                        && c.application.content == "durable final text")
                );
                assert!(!receiver.latched);
            }
            let outcomes: Vec<serde_json::Value> = std::fs::read_to_string(journal.path())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(outcomes.len(), 4);
            assert!(outcomes[1]["candidate"].is_null());
            assert_eq!(outcomes[3]["candidate"]["application"]["kind"], 9);

            // Actual post-join commit: the same native-valid wider policy must
            // roll back inside SQL before durable state, then succeed without
            // the private enrolled-template guard as a causal control.
            let before = receiver.engine.group_authority(&group).unwrap().facts.epoch;
            let mut wider = AgentTextStreamQuicPolicyV1::user_to_agent_default();
            wider.max_plaintext_frame_len = 8192;
            let SendResult::GroupEvolution { msg: commit, .. } = inviter
                .do_send_update_app_components(
                    group.clone(),
                    vec![wider.to_app_component_data().unwrap()],
                )
                .await
                .unwrap()
            else {
                panic!("policy commit")
            };
            let mut capture = crate::protected_merge::Capture::for_group(group.clone());
            capture.template = Some(template);
            receiver.engine.receiver_merge_capture = Some(capture);
            assert!(receiver.engine.ingest(commit.clone()).await.is_err());
            assert_eq!(
                receiver.engine.storage.get_group(&group).unwrap().epoch,
                before
            );
            // Independently joined native control accepts the exact commit;
            // the protected receiver never retries its refused original.
            assert!(matches!(
                native_control.ingest(commit.clone()).await.unwrap(),
                cgka_traits::ingest::IngestOutcome::Buffered { .. }
            ));
            // Replay the actual buffered commit under the enrolled policy.
            // Refusal must roll back native group state and the durable row;
            // an independently joined ordinary engine is the positive control.
            assert!(matches!(
                replay_control.ingest(commit).await.unwrap(),
                cgka_traits::ingest::IngestOutcome::Buffered { .. }
            ));
            let control_before = replay_control.storage.get_group(&group).unwrap().epoch;
            let ordinary = crate::openmls_projection::canonicalize_stored_openmls_messages(
                &replay_control.storage,
                &group,
                crate::canonicalization::CanonicalizationState {
                    current_tip_epoch: control_before.0,
                    retained_anchor_epoch: control_before.0,
                    last_convergence_relevant_input_ms: 0,
                    seen_message_ids: Default::default(),
                },
                vec![],
                Default::default(),
                u64::MAX,
            )
            .unwrap();
            assert!(
                !ordinary.accepted_commits.is_empty(),
                "ordinary replay accepts wider commit"
            );
            let refusal = crate::openmls_projection::apply_openmls_canonicalization_result_with_profile_policy(
                &replay_control.storage, &group, &ordinary, 64,
                crate::openmls_projection::ReplayProfilePolicy {
                    receiver_template: Some(template), ..Default::default()
                },
            ).unwrap_err();
            assert!(
                matches!(refusal,
                    crate::openmls_projection::OpenMlsProjectionError::InvalidCommit { ref reason, .. }
                    if reason.contains("protected receiver replayed state") && reason.contains("protected capability policy mismatch")
                ),
                "exact protected-policy rejection required, got {refusal:?}"
            );
            assert_eq!(
                replay_control.storage.get_group(&group).unwrap().epoch,
                control_before
            );
            let mut replay_capture = crate::protected_merge::Capture::for_group(group.clone());
            replay_capture.template = Some(template);
            replay_control.receiver_merge_capture = Some(replay_capture);
            assert!(
                replay_control
                    .advance_convergence_inputs_until_settled(&group, u64::MAX)
                    .await
                    .unwrap()
            );
            assert_eq!(
                replay_control.storage.get_group(&group).unwrap().epoch,
                control_before
            );
            replay_control
                .with_mls_group(&group, |native| template.validate_group(native))
                .unwrap();
            // The same receiver policy captured for a different group must not
            // constrain this independently joined group's canonical replay.
            let mut unrelated = crate::protected_merge::Capture::for_group(
                cgka_traits::types::GroupId::new(vec![0x99; 16]),
            );
            unrelated.template = Some(template);
            native_control.receiver_merge_capture = Some(unrelated);
            assert!(
                native_control
                    .advance_convergence_inputs_until_settled(&group, u64::MAX)
                    .await
                    .unwrap()
            );
            assert!(
                native_control
                    .with_mls_group(&group, |native| template.validate_group(native))
                    .is_err()
            );
        } else {
            assert!(result.is_none());
            assert_eq!(original.metadata().unwrap().len(), 0);
            assert!(recipient.storage.list_groups().unwrap().is_empty());
            assert!(
                recipient
                    .storage
                    .list_pending_application_events()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                crate::key_package::durably_owned_key_packages(
                    &recipient.storage,
                    cgka_traits::group::ProtocolProfile::Current
                )
                .unwrap()
                .len(),
                1
            );
            // Same bytes still pass unmodified native rules: the handling-policy
            // refusal rolled back group, package and dedup, and spent no intent.
            assert!(
                recipient
                    .receiver_join_enrolled(wire, intent(), constraint(routing_only_v1()))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
}

#[tokio::test]
async fn extra_required_primitives_refuse_before_intent_with_native_valid_controls() {
    use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
    for extra in [
        Capability::Proposal(10),
        Capability::Extension(0xf2d2),
        Capability::AppComponent(0x9000),
    ] {
        // Deliberately wider test engines establish native validity, not a
        // permitted protected template or a production advertisement path.
        let wide = || {
            let keys = nostr::Keys::generate();
            let mut registry = bounded_app_receiver_v1().registry();
            registry.register(
                Feature("fixture-extra"),
                CapabilityRequirement {
                    requires: extra,
                    level: RequirementLevel::Required,
                    description: "native-valid negative control",
                },
            );
            let mut components = bounded_app_receiver_v1().components();
            if let Capability::AppComponent(id) = extra {
                components.insert(id);
            }
            EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
                .supported_app_components(components)
                .feature_registry(registry)
                .identity(keys.public_key().to_bytes().to_vec())
                .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
                .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(keys)))
                .build()
                .unwrap()
        };
        let mut inviter = wide();
        let mut recipient = wide();
        let mut kp = recipient.fresh_key_package().await.unwrap();
        let metadata = crate::key_package_metadata(&kp).unwrap();
        assert!(
            bounded_app_receiver_v1()
                .validate_metadata(&metadata)
                .is_err()
        );
        let reference = hex::decode(metadata.key_package_ref_hex).unwrap();
        kp.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::types::MessageId::new(vec![8; 32]),
        });
        let created = inviter
            .create_group(CreateGroupRequest {
                name: "unsupported required primitive".into(),
                description: String::new(),
                members: vec![kp],
                required_features: vec![Feature("fixture-extra")],
                initial_admins: vec![],
                app_components: {
                    let mut data = vec![cgka_traits::app_components::AppComponentData {
                        component_id: cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID,
                        data: cgka_traits::app_components::encode_nostr_routing_v1(
                            &cgka_traits::app_components::NostrRoutingV1::new(
                                [7; 32],
                                vec!["wss://bounded.invalid".into()],
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    }];
                    if let Capability::AppComponent(id) = extra {
                        data.push(cgka_traits::app_components::AppComponentData {
                            component_id: id,
                            data: vec![],
                        });
                    }
                    data
                },
            })
            .await;
        if let Capability::AppComponent(_) = extra {
            assert!(
                matches!(created,Err(cgka_traits::EngineError::Other(ref error)) if error.contains("unsupported required component"))
            );
            assert!(recipient.storage.list_groups().unwrap().is_empty());
            assert_eq!(
                crate::key_package::durably_owned_key_packages(
                    &recipient.storage,
                    cgka_traits::group::ProtocolProfile::Current
                )
                .unwrap()
                .len(),
                1
            );
            continue;
        }
        let (group, send) = created.unwrap();
        let SendResult::FoundingGroupCreated { mut welcomes } = send else {
            panic!("Current")
        };
        let wire = welcomes.remove(0);
        let root = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(root.path().join("intent"))
            .unwrap();
        let intent = || JoinIntent {
            file: file.try_clone().unwrap(),
            directory: File::open(root.path()).unwrap(),
        };
        let constraint = |template| JoinConstraint {
            group: group.clone(),
            expected_welcomer: inviter.self_id(),
            operators: vec![inviter.self_id()],
            key_package_ref: reference.clone(),
            template,
        };
        assert!(
            recipient
                .receiver_join_enrolled(
                    wire.clone(),
                    intent(),
                    constraint(bounded_app_receiver_v1())
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(file.metadata().unwrap().len(), 0);
        assert!(recipient.storage.list_groups().unwrap().is_empty());
        assert!(
            recipient
                .storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::key_package::durably_owned_key_packages(
                &recipient.storage,
                cgka_traits::group::ProtocolProfile::Current
            )
            .unwrap()
            .len(),
            1
        );
        assert!(
            recipient
                .receiver_join_enrolled(wire, intent(), constraint(routing_only_v1()))
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn native_media_validation_refuses_malformed_v2_and_mixed_policy() {
    use cgka_traits::app_components::*;
    for mixed in [false, true] {
        let mut inviter = client(bounded_app_receiver_v1());
        let mut recipient = client(bounded_app_receiver_v1());
        let mut kp = recipient.fresh_key_package().await.unwrap();
        kp.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::types::MessageId::new(vec![9; 32]),
        });
        let mut components = vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: encode_nostr_routing_v1(
                &NostrRoutingV1::new([7; 32], vec!["wss://bounded.invalid".into()]).unwrap(),
            )
            .unwrap(),
        }];
        components.push(AppComponentData {
            component_id: GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
            data: if mixed {
                encode_encrypted_media_policy_v2(
                    &EncryptedMediaPolicyV2::blossom_default(vec!["https://media.invalid".into()])
                        .unwrap(),
                )
                .unwrap()
            } else {
                vec![0xff]
            },
        });
        if mixed {
            components.push(AppComponentData {
                component_id: GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
                data: encode_encrypted_media_policy_v1(
                    &EncryptedMediaPolicyV1::blossom_default(
                        vec!["https://media.invalid".into()],
                        false,
                    )
                    .unwrap(),
                )
                .unwrap(),
            });
        }
        assert!(
            inviter
                .create_group(CreateGroupRequest {
                    name: "native media refusal".into(),
                    description: String::new(),
                    members: vec![kp],
                    required_features: vec![],
                    initial_admins: vec![],
                    app_components: components
                })
                .await
                .is_err()
        );
        assert!(inviter.storage.list_groups().unwrap().is_empty());
        assert!(recipient.storage.list_groups().unwrap().is_empty());
        assert!(
            recipient
                .storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::key_package::durably_owned_key_packages(
                &recipient.storage,
                cgka_traits::group::ProtocolProfile::Current
            )
            .unwrap()
            .len(),
            1
        );
    }
}

#[tokio::test]
async fn unrequired_group_context_extension_refuses_before_intent_with_native_control() {
    use crate::provider::EngineOpenMlsProvider;
    use cgka_traits::engine::SendIntent;
    use openmls::prelude::{Extension, Extensions, ExternalSender, MlsGroup};
    use openmls_traits::OpenMlsProvider;
    let mut inviter = client(bounded_app_receiver_v1());
    let mut recipient = client(bounded_app_receiver_v1());
    let mut kp = recipient.fresh_key_package().await.unwrap();
    let reference = hex::decode(
        crate::key_package_metadata(&kp)
            .unwrap()
            .key_package_ref_hex,
    )
    .unwrap();
    kp.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: cgka_traits::types::MessageId::new(vec![0x35; 32]),
    });
    let (group, _) = inviter
        .create_group(CreateGroupRequest {
            name: "unrequired outer extension".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
            app_components: vec![cgka_traits::app_components::AppComponentData {
                component_id: cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID,
                data: cgka_traits::app_components::encode_nostr_routing_v1(
                    &cgka_traits::app_components::NostrRoutingV1::new(
                        [7; 32],
                        vec!["wss://bounded.invalid".into()],
                    )
                    .unwrap(),
                )
                .unwrap(),
            }],
        })
        .await
        .unwrap();
    {
        // Actual OpenMLS state transition on the disposable inviter, not a
        // serialized Welcome rewrite or a production policy escape hatch.
        let provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
            &inviter.crypto,
            inviter.storage.mls_storage(),
        );
        let mut native = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(group.as_slice()),
        )
        .unwrap()
        .unwrap();
        bounded_app_receiver_v1().validate_group(&native).unwrap();
        let mut extensions: Vec<_> = native.extensions().iter().cloned().collect();
        let leaf = native.own_leaf_node().unwrap();
        extensions.push(Extension::ExternalSenders(vec![ExternalSender::new(
            leaf.signature_key().clone(),
            leaf.credential().clone(),
        )]));
        let extensions = Extensions::from_vec(extensions).unwrap();
        let bundle = native
            .commit_builder()
            .propose_group_context_extensions(extensions)
            .unwrap()
            .load_psks(provider.storage())
            .unwrap()
            .build(
                provider.rand(),
                provider.crypto(),
                &inviter.identity.signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&provider)
            .unwrap();
        drop(bundle);
        native.merge_pending_commit(&provider).unwrap();
        assert!(
            native
                .extensions()
                .iter()
                .any(|extension| matches!(extension, Extension::ExternalSenders(_)))
        );
        assert!(
            !crate::capability_manager::required_capabilities_from_group(&native)
                .extensions
                .contains(&5)
        );
    }
    let sent = inviter
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution { mut welcomes, .. } = sent else {
        panic!("invite commit")
    };
    let wire = welcomes.remove(0);
    let root = tempfile::tempdir().unwrap();
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(root.path().join("intent"))
        .unwrap();
    let intent = || JoinIntent {
        file: file.try_clone().unwrap(),
        directory: File::open(root.path()).unwrap(),
    };
    let constraint = |template| JoinConstraint {
        group: group.clone(),
        expected_welcomer: inviter.self_id(),
        operators: vec![inviter.self_id()],
        key_package_ref: reference.clone(),
        template,
    };
    assert!(
        recipient
            .receiver_join_enrolled(
                wire.clone(),
                intent(),
                constraint(bounded_app_receiver_v1())
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(file.metadata().unwrap().len(), 0);
    assert!(recipient.storage.list_groups().unwrap().is_empty());
    assert!(
        recipient
            .storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        crate::key_package::durably_owned_key_packages(
            &recipient.storage,
            cgka_traits::group::ProtocolProfile::Current
        )
        .unwrap()
        .len(),
        1
    );
    assert!(
        recipient
            .receiver_join_enrolled(wire, intent(), constraint(routing_only_v1()))
            .await
            .unwrap()
            .is_some()
    );
}

#[test]
fn exact_closed_policy_codec_matches_design_bytes_and_rejects_cross_binding() {
    for template in [
        routing_only_v1(),
        bounded_app_receiver_v1(),
        admind_receiver_v1(),
    ] {
        let raw = template.canonical_policy();
        let golden: &[u8] = if template == routing_only_v1() {
            include_bytes!("../tests/fixtures/receiver-v3/routing-only-v1.json")
        } else if template == bounded_app_receiver_v1() {
            include_bytes!("../tests/fixtures/receiver-v3/bounded-app-receiver-v1.json")
        } else {
            include_bytes!("../tests/fixtures/receiver-v3/admind-receiver-v1.json")
        };
        assert_eq!(raw, golden);
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["template"], template.id());
        assert_eq!(
            value["mls_proposals"],
            if template == admind_receiver_v1() {
                serde_json::json!([8, 10])
            } else {
                serde_json::json!([8])
            }
        );
        assert_eq!(serde_json::to_vec(&value).unwrap(), raw);
        assert_eq!(
            Template::from_policy(template.id(), &template.policy_sha256()).unwrap(),
            template
        );
        assert!(Template::from_policy(template.id(), &"00".repeat(32)).is_err());
    }
    assert!(
        Template::from_policy(
            routing_only_v1().id(),
            &bounded_app_receiver_v1().policy_sha256()
        )
        .is_err()
    );
    assert!(Template::from_policy("default", &routing_only_v1().policy_sha256()).is_err());
}

#[tokio::test]
#[ignore = "requires separately built actual0.13 disposable helper test binary"]
async fn actual_v013_welcome_and_commit_enter_exact_admind_v010_policy() {
    use cgka_traits::{GroupId, MemberId, TransportMessage};
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Reply {
        group: GroupId,
        welcomer: MemberId,
        welcome: TransportMessage,
        commit: TransportMessage,
    }
    let template = admind_receiver_v1();
    let mut recipient = client(template);
    let kp = recipient.fresh_key_package().await.unwrap();
    let metadata = crate::key_package_metadata(&kp).unwrap();
    template.validate_metadata(&metadata).unwrap();
    assert_eq!(metadata.mls_proposals, [8, 10]);
    let mut unsupported = metadata.clone();
    unsupported.mls_proposals.push(9);
    assert!(template.validate_metadata(&unsupported).is_err());
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("package.json"),
        serde_json::to_vec(&kp).unwrap(),
    )
    .unwrap();
    let binary =
        std::env::var_os("HD_INTEROP_V013_TEST").expect("actual separately built0.13 helper");
    let child = std::process::Command::new(binary)
        .args([
            "--ignored",
            "client::export_current_admind_receiver_interop_fixture",
            "--exact",
            "--nocapture",
        ])
        .env("HD_INTEROP_ROOT", root.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "0.13 helper failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let reply: Reply =
        serde_json::from_slice(&std::fs::read(root.path().join("reply.json")).unwrap()).unwrap();
    let constraint = |template| JoinConstraint {
        group: reply.group.clone(),
        expected_welcomer: reply.welcomer.clone(),
        operators: vec![reply.welcomer.clone()],
        key_package_ref: hex::decode(&metadata.key_package_ref_hex).unwrap(),
        template,
    };
    let wrong_intent = crate::protected_join::tests::intent(root.path());
    assert!(
        recipient
            .receiver_join_enrolled(
                reply.welcome.clone(),
                wrong_intent,
                constraint(bounded_app_receiver_v1())
            )
            .await
            .unwrap()
            .is_none(),
        "old policy must refuse required Proposal10 rather than silently widening"
    );
    assert!(recipient.storage.list_groups().unwrap().is_empty());
    assert_eq!(
        crate::key_package::durably_owned_key_packages(
            &recipient.storage,
            cgka_traits::group::ProtocolProfile::Current
        )
        .unwrap()
        .len(),
        1
    );
    std::fs::remove_file(root.path().join("join-intent")).unwrap();
    let evidence = recipient
        .receiver_join_enrolled(
            reply.welcome,
            crate::protected_join::tests::intent(root.path()),
            constraint(template),
        )
        .await
        .unwrap()
        .expect("actual0.13 native Welcome accepted by exact0.10 policy");
    assert_eq!(evidence.group, reply.group);
    assert_eq!(
        recipient.storage.list_groups().unwrap(),
        vec![reply.group.clone()]
    );
    let before = recipient.group_record(&reply.group).unwrap().epoch;
    let mut capture = crate::protected_merge::Capture::for_group(reply.group.clone());
    capture.template = Some(template);
    recipient.receiver_merge_capture = Some(capture);
    let outcome = recipient.ingest(reply.commit).await.unwrap();
    eprintln!("actual0.13 commit outcome: {outcome:?}");
    recipient
        .advance_convergence_inputs_until_settled(&reply.group, u64::MAX)
        .await
        .unwrap();
    let after = recipient.group_record(&reply.group).unwrap().epoch;
    assert!(
        after > before,
        "actual0.13 postjoin native commit advances receiver epoch"
    );
}
