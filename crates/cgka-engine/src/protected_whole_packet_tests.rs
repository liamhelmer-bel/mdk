//! Disposable actual Product child/Git + real MLS; relay ACK and HTTPS/rendering
//! are explicit fixtures. No runtime custody, operator or deployment authority.
use super::*;
use crate::Engine;
use cgka_traits::GroupId;
use nostr::base64::{Engine as _, engine::general_purpose::STANDARD};
use std::process::Command;

const PRODUCT_HEAD: &str = "faec83f17b92d3251e3118942c982661b085be59";

#[tokio::test]
#[ignore = "qualification requires pinned Product checkout and Python test dependencies; no live relay"]
async fn current_whole_product_packet_real_mls_approval_consumes_exact_checked_frame() {
    whole_product_exchange(false).await;
}

#[tokio::test]
#[ignore = "disposable maximum-original native MLS qualification"]
async fn current_maximum_original_real_mls_consumed_frame() {
    whole_product_exchange(true).await;
}

async fn whole_product_exchange(maximum_original: bool) {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }

    let product = std::env::var_os("HETERODYNE_QUALIFICATION_PRODUCT")
        .expect("explicit test Product checkout");
    let python = std::env::var_os("HETERODYNE_QUALIFICATION_PYTHON").expect("explicit test Python");
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&product)
        .output()
        .unwrap();
    assert!(head.status.success());
    assert_eq!(String::from_utf8(head.stdout).unwrap().trim(), PRODUCT_HEAD);
    let status = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(&product)
        .output()
        .unwrap();
    assert!(status.status.success() && status.stdout.is_empty());
    let (factory, operator, root, relay) = current_routed_fixture().await;
    assert_eq!(factory.receiver.group.as_slice().len(), 16);
    let transport_group = [7; 32];
    let binding = super::super::owned_producer::GroupBinding::read(
        &factory.receiver.engine,
        &factory.receiver.group,
        &transport_group,
    )
    .unwrap();
    let fixture = root.path().join("current-whole-packet.json");
    let generator = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/current_whole_packet.py");
    let mut generate = Command::new(&python);
    generate.arg(&generator);
    if maximum_original {
        generate.arg("--pad-original");
    }
    let generated = generate
        .arg("--product")
        .arg(&product)
        .arg("--output")
        .arg(&fixture)
        .arg("--group-hex")
        .arg(hex::encode(factory.receiver.group.as_slice()))
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "test-only Product generator failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let fixture_bytes = std::fs::read(&fixture).unwrap();
    if maximum_original {
        let output = std::env::var_os("HETERODYNE_QUALIFICATION_CONSUMED").unwrap();
        std::fs::write(
            std::path::Path::new(&output).with_extension("product.json"),
            &fixture_bytes,
        )
        .unwrap();
        for suffix in ["producer.json", "packet.json"] {
            std::fs::copy(
                fixture.with_extension(suffix),
                std::path::Path::new(&output).with_extension(suffix),
            )
            .unwrap();
        }
    }
    let payload: serde_json::Value = serde_json::from_slice(&fixture_bytes).unwrap();
    assert_eq!(payload["product_head"], PRODUCT_HEAD);
    assert!(
        payload["qualification"]
            .as_str()
            .unwrap()
            .contains("synthetic HTTPS/rendering")
    );
    let raw = STANDARD
        .decode(payload["output_original_base64"].as_str().unwrap())
        .unwrap();
    let ask = super::super::owned_producer::qualification_original(&raw, &binding).unwrap();
    assert_eq!(ask.expected_group, factory.receiver.group);
    assert_eq!(
        payload["output"]["group_hex"],
        hex::encode(factory.receiver.group.as_slice())
    );
    let wrong_route_binding = super::super::owned_producer::GroupBinding::read(
        &factory.receiver.engine,
        &factory.receiver.group,
        &[8; 32],
    );
    assert!(matches!(
        wrong_route_binding,
        Err(ReceiverHold::ChangedState)
    ));
    // Routing32 is grammatically valid Product input but the wrong domain.
    // Generate a genuine second card rather than rewriting card group context.
    let route_fixture = root.path().join("routing-domain-packet.json");
    let wrong = Command::new(&python)
        .arg(&generator)
        .arg("--product")
        .arg(&product)
        .arg("--output")
        .arg(&route_fixture)
        .arg("--group-hex")
        .arg(hex::encode(transport_group))
        .output()
        .unwrap();
    assert!(
        wrong.status.success(),
        "{}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    let wrong_payload: serde_json::Value =
        serde_json::from_slice(&std::fs::read(route_fixture).unwrap()).unwrap();
    let wrong_raw = STANDARD
        .decode(wrong_payload["output_original_base64"].as_str().unwrap())
        .unwrap();
    // The same genuinely generated routing-domain card passes a deliberately
    // matching native=routing control, isolating the actual native16 mismatch.
    super::super::owned_producer::qualification_correspondence_control(
        &wrong_raw,
        GroupId::new(transport_group.to_vec()),
        transport_group,
    )
    .expect("matching-domain mechanical control");
    assert!(matches!(
        super::super::owned_producer::qualification_original(&wrong_raw, &binding),
        Err(ReceiverHold::ChangedState)
    ));
    assert_eq!(
        digest(&ask.operation),
        payload["output"]["operation_original_sha256"]
    );
    assert_eq!(
        digest(&ask.operation_canonical),
        payload["output"]["packet_sha256"]
    );
    assert_eq!(
        digest(&ask.original_request),
        payload["output"]["request_sha256"]
    );
    if maximum_original {
        assert_eq!(ask.operation.len(), 32768);
    }
    let consumed = qualify_owned_exchange(factory, operator, root, relay, ask).await;
    if maximum_original {
        let frame = serde_json::to_vec(&consumed).unwrap();
        assert!(frame.len() > 65536);
        assert!(frame.len() <= 262144);
        let output = std::env::var_os("HETERODYNE_QUALIFICATION_CONSUMED")
            .expect("explicit disposable native output path");
        let exact = std::fs::read(output).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&exact).unwrap(),
            consumed
        );
        eprintln!("actual maximum-original Consumed: {} bytes", frame.len());
    }
}

async fn qualify_owned_exchange(
    mut factory: SemanticFactory<SqliteAccountStorage>,
    mut operator: Engine<SqliteAccountStorage>,
    root: tempfile::TempDir,
    relay: Arc<super::super::tests::Relay>,
    ask: OriginalAsk,
) -> serde_json::Value {
    let transport_group = [7; 32];
    let expected = serde_json::to_value(&ask).unwrap();
    let operation = digest(&ask.operation);
    let canonical = digest(&ask.operation_canonical);
    let id = ask.ask_id.clone();
    assert_ne!(ask.operation, ask.operation_canonical);
    assert_eq!(ask.card_chunks.len(), 1);
    assert!(ask.card_chunks[0].contains("OUTAGE"));
    let packet: serde_json::Value = serde_json::from_slice(&ask.operation_canonical).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    assert!(u128::from(packet["release"]["not_before_ns"].as_u64().unwrap()) <= now);
    assert!(now < u128::from(packet["outage"]["deadline_ns"].as_u64().unwrap()));
    // Real exchange owns activation, post, ingress/EOSE, preconsume check and frame.
    factory
        .enable_catalog(super::super::tests::cache(root.path(), "exchange-cache"))
        .unwrap();
    let expected_operator = operator.self_id();
    let native = factory.receiver.group.clone();
    let adapter = factory.transport.clone();
    let (tx, rx) = tokio::sync::broadcast::channel(16);
    let forwarder = forward_notifications(rx, adapter.clone(), tempfile::tempfile().unwrap());
    let keepalive = tx.clone();
    let (mut sender, mut consumer) = UnixStream::pair().unwrap();
    let mut before_eose = consumer.try_clone().unwrap();
    let subscriptions_before = relay.subscriptions.lock().unwrap().len();
    let expected_card = ask.card_chunks[0].clone();
    let driver = tokio::spawn(async move {
        let wire = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(wire) = relay.wires.lock().unwrap().first().cloned() {
                    break wire;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded actual card publication");
        operator.ingest(wire).await.unwrap();
        let target = operator
            .drain_events()
            .into_iter()
            .find_map(|event| match event {
                cgka_traits::GroupEvent::MessageReceived {
                    group_id, payload, ..
                } => {
                    assert_eq!(group_id, native);
                    let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                    assert_eq!(value["content"], expected_card);
                    Some(value["id"].as_str().unwrap().to_owned())
                }
                _ => None,
            })
            .expect("actual published card must reach operator");
        let reaction = MarmotAppEvent::new(
            hex::encode(operator.self_id().as_slice()),
            1,
            MARMOT_APP_EVENT_KIND_REACTION,
            vec![vec!["e".into(), target]],
            "👍",
        );
        let cgka_traits::SendResult::ApplicationMessage { msg, .. } = operator
            .send(cgka_traits::SendIntent::AppMessage {
                group_id: native,
                payload: reaction.encode().unwrap(),
                expected_epoch: None,
            })
            .await
            .unwrap()
        else {
            panic!("actual MLS reply");
        };
        tx.send(nostr_sdk::RelayPoolNotification::Event {
            relay_url: "wss://semantic.invalid".parse().unwrap(),
            subscription_id: nostr::SubscriptionId::new("fixture"),
            event: Box::new(serde_json::from_slice(&msg.payload).unwrap()),
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        before_eose.set_nonblocking(true).unwrap();
        assert_eq!(
            before_eose.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        before_eose.set_nonblocking(false).unwrap();
        let subscriptions = relay.subscriptions.lock().unwrap().clone();
        assert!(subscriptions.len() > subscriptions_before);
        for subscription in subscriptions {
            tx.send(nostr_sdk::RelayPoolNotification::Message {
                relay_url: "wss://semantic.invalid".parse().unwrap(),
                message: nostr::RelayMessage::EndOfStoredEvents(std::borrow::Cow::Owned(
                    nostr::SubscriptionId::new(subscription.subscription_id()),
                )),
            })
            .unwrap();
        }
        assert_eq!(relay.wires.lock().unwrap().len(), 1);
    });
    let nonce = [0x39; 32];
    // Fixture process pins are selected BEFORE the real exchange, from the
    // actual retained journal enrollment. They are not installed owner custody.
    let crate::protected_receiver::ReceiverJournal::Ordered(journal) = &factory.receiver.journal
    else {
        panic!("ordered native journal required")
    };
    let enrollment = journal.enrollment().unwrap();
    let enrollment_sha = digest(&serde_json::to_vec(&enrollment).unwrap());
    let process = serde_json::to_vec(&serde_json::json!({
        "schema":"heterodyne-protected-receiver-process.v3", "enrollment":enrollment,
        "receiver_uid":899,"consumer_uid":898,"endpoints":["wss://semantic.invalid"],
        "wait_seconds":15,
    }))
    .unwrap();
    if let Some(output) = std::env::var_os("HETERODYNE_QUALIFICATION_CONSUMED") {
        std::fs::write(
            std::path::Path::new(&output).with_extension("process.json"),
            &process,
        )
        .unwrap();
    }
    exchange(
        &mut factory,
        &adapter,
        &forwarder,
        &mut sender,
        Session {
            ask,
            transport_group: transport_group.to_vec(),
            wait_seconds: 15,
            profile_sha: digest(&process),
            enrollment_sha,
            journal_sha: enrollment.source_profile_sha256,
            installation_index_sha256: enrollment.installation_index_sha256,
            installation_source_sha256: enrollment.installation_source_sha256,
            capability_template: enrollment.capability_template,
            capability_policy_sha256: enrollment.capability_policy_sha256,
            installation: None,
            nonce,
        },
    )
    .await
    .unwrap();
    driver.await.unwrap();
    factory.load_retained(&id).unwrap();
    assert!(factory.asks[&id].consumed);
    assert!(factory.consume(&id, &canonical).is_err());
    let key = consumed_key(&factory, &id, &operation).unwrap();
    let mut prefix = [0; 4];
    consumer.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0; u32::from_be_bytes(prefix) as usize];
    consumer.read_exact(&mut frame).unwrap();
    if let Some(output) = std::env::var_os("HETERODYNE_QUALIFICATION_CONSUMED") {
        std::fs::write(output, &frame).unwrap();
    }
    let result: serde_json::Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(result["schema"], "heterodyne-owned-consumed.v3");
    assert_eq!(result["nonce_hex"], hex::encode(nonce));
    assert_eq!(result["original"], expected);
    assert_eq!(result["receipt"]["decision"], "Approve");
    assert_eq!(
        result["receipt"]["operator"],
        serde_json::to_value(expected_operator).unwrap()
    );
    assert_eq!(result["receipt"]["operation_sha256"], operation);
    assert_eq!(
        result["consumption_key"]["original_operation_sha256"],
        operation
    );
    assert_eq!(result["consumption_key"]["ask_id"], id);
    let records: Vec<serde_json::Value> =
        std::fs::read_to_string(root.path().join("receiver/journal"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    let consumed = records
        .iter()
        .find(|r| r["body"]["kind"] == "consumed")
        .unwrap();
    let card = records
        .iter()
        .find(|r| r["body"]["kind"] == "card-complete")
        .unwrap();
    assert_eq!(result["consumption_key"], consumed["body"]["key"]);
    assert_eq!(
        result["consumption_key"]["header_sha256"],
        records[0]["sha256"]
    );
    assert_eq!(
        result["consumption_key"]["card_complete_sequence"],
        card["sequence"]
    );
    assert!(factory.consume(&id, &operation).is_err());
    assert_eq!(
        serde_json::to_value(&key).unwrap(),
        result["consumption_key"]
    );
    drop(consumer);
    assert!(write_frame(&mut sender, &frame).is_err());
    drop(keepalive);
    forwarder.abort();
    assert!(factory.asks[&id].consumed); // lost reply never reverses durable one-use.
    result
}

// Current profile, actual Schnorr account proof signer and NIP-59/445 peeler.
// Journal enrollment below is disposable test evidence, not host custody.
async fn current_routed_fixture() -> (
    SemanticFactory<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    tempfile::TempDir,
    Arc<super::super::tests::Relay>,
) {
    use cgka_traits::{
        app_components::{
            AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, default_group_components,
            encode_nostr_routing_v1,
        },
        engine::{CreateGroupRequest, SendResult},
        transport::TransportEnvelope,
    };
    use std::os::unix::fs::PermissionsExt;
    let client = || {
        let keys = nostr::Keys::generate();
        let mut supported = default_group_components();
        supported.insert(NOSTR_ROUTING_COMPONENT_ID);
        EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
            .supported_app_components(supported)
            .identity(keys.public_key().to_bytes().to_vec())
            .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
            .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(keys)))
            .build()
            .unwrap()
    };
    let mut operator = client();
    let mut controller = client();
    let mut kp = controller.fresh_key_package().await.unwrap();
    kp.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: cgka_traits::types::MessageId::new(vec![4; 32]),
    });
    let components = vec![AppComponentData {
        component_id: NOSTR_ROUTING_COMPONENT_ID,
        data: encode_nostr_routing_v1(
            &NostrRoutingV1::new([7; 32], vec!["wss://semantic.invalid".into()]).unwrap(),
        )
        .unwrap(),
    }];
    let (group, sent) = operator
        .create_group(CreateGroupRequest {
            name: "current protected qualification".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: components,
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = sent else {
        panic!("current profile must create canonical founding group")
    };
    let welcome = welcomes
        .into_iter()
        .find(|w| {
            matches!(&w.envelope,
        TransportEnvelope::Welcome{recipient} if recipient == &controller.self_id())
        })
        .unwrap();
    controller.join_welcome(welcome).await.unwrap();
    operator.drain_events();
    controller.drain_events();
    let root = tempfile::tempdir().unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema":"heterodyne-receiver-expiry.v1", "max_approval_lifetime_ms":60000,
    }))
    .unwrap();
    std::fs::write(root.path().join("profile"), &bytes).unwrap();
    std::fs::set_permissions(
        root.path().join("profile"),
        std::fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let operators = vec![operator.self_id()];
    let (journal, _) = crate::protected_receiver::tests::ordered_fixture_profile(
        root.path(),
        &controller,
        &group,
        &operators,
        digest(&bytes),
    );
    let receiver =
        ProtectedReceiver::new(controller, group, operators, tempfile::tempfile().unwrap())
            .unwrap();
    let relay = Arc::new(super::super::tests::Relay::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    adapter
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
        adapter,
        vec![TransportEndpoint::from("wss://semantic.invalid")],
    )
    .unwrap();
    factory.receiver.journal = crate::protected_receiver::ReceiverJournal::Ordered(journal);
    let factory = factory
        .with_expiry_profile(File::open(root.path().join("profile")).unwrap())
        .unwrap();
    (factory, operator, root, relay)
}

#[tokio::test]
async fn current_native_group_context_checks_both_enrolled_domains_and_requires_routing() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }

    let (mut factory, _, _, _) = current_routed_fixture().await;
    let engine = &factory.receiver.engine;
    let group = &factory.receiver.group;
    assert_eq!(group.as_slice().len(), 16);
    assert!(super::super::owned_producer::GroupBinding::read(engine, group, &[7; 32]).is_ok());
    assert!(matches!(
        super::super::owned_producer::GroupBinding::read(engine, group, &[8; 32]),
        Err(ReceiverHold::ChangedState)
    ));
    assert!(matches!(
        super::super::owned_producer::GroupBinding::read(
            engine,
            &GroupId::new(vec![0; 16]),
            &[7; 32]
        ),
        Err(ReceiverHold::ChangedState)
    ));
    let (unrouted, _) = factory
        .receiver
        .engine
        .create_group(cgka_traits::engine::CreateGroupRequest {
            name: "unrouted current group".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    // No direct-native fallback, even when a profile supplies that same identity.
    assert!(matches!(
        super::super::owned_producer::GroupBinding::read(
            &factory.receiver.engine,
            &unrouted,
            unrouted.as_slice(),
        ),
        Err(ReceiverHold::ChangedState)
    ));
}

#[tokio::test]
async fn owned_exchange_refuses_wrong_native_or_transport_before_external_publication() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }

    for wrong_native in [true, false] {
        let (mut factory, _, _, relay) = current_routed_fixture().await;
        let mut ask = super::super::tests::finite_original("ask3", &factory.receiver.group);
        let mut route = vec![7; 32];
        if wrong_native {
            ask.expected_group = GroupId::new(vec![0; 16]);
        } else {
            route = vec![8; 32];
        }
        let session = Session {
            ask,
            transport_group: route,
            wait_seconds: 1,
            profile_sha: "01".repeat(32),
            enrollment_sha: "02".repeat(32),
            journal_sha: "03".repeat(32),
            installation_index_sha256: "04".repeat(32),
            installation_source_sha256: "05".repeat(32),
            capability_template: crate::protected_capability_policy::routing_only_v1()
                .id()
                .into(),
            capability_policy_sha256: crate::protected_capability_policy::routing_only_v1()
                .policy_sha256(),
            installation: None,
            nonce: [0x61; 32],
        };
        let adapter = factory.transport.clone();
        let (_tx, rx) = tokio::sync::broadcast::channel(2);
        let forwarder = forward_notifications(rx, adapter.clone(), tempfile::tempfile().unwrap());
        let (mut receiver, mut consumer) = UnixStream::pair().unwrap();
        let subscriptions_before = relay.subscriptions.lock().unwrap().len();
        assert!(matches!(
            exchange(&mut factory, &adapter, &forwarder, &mut receiver, session).await,
            Err(ReceiverHold::ChangedState)
        ));
        assert!(relay.wires.lock().unwrap().is_empty());
        assert_eq!(
            relay.subscriptions.lock().unwrap().len(),
            subscriptions_before
        );
        assert!(factory.asks.is_empty());
        let mut length = [0; 4];
        consumer.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        consumer.read_exact(&mut bytes).unwrap();
        let hold: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(hold["schema"], "heterodyne-owned-receiver-hold.v1");
        assert_eq!(hold["automatic_replay_permitted"], false);
        forwarder.abort();
    }
}

#[tokio::test]
#[ignore = "requires disposable namespace with unchanged Product closure and verified loopback TLS"]
async fn unchanged_installed_producer_real_tls_then_real_mls_exchange() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }

    use super::super::owned_producer::{Inputs, InstalledProducer};
    let fixture = std::path::Path::new("/opt/producer-qualification");
    let original = std::fs::read(fixture.join("original.json")).unwrap();
    let closure =
        serde_json::from_slice(&std::fs::read(fixture.join("closure.json")).unwrap()).unwrap();
    let inputs = Inputs {
        profile: File::open(fixture.join("profile.json")).unwrap(),
        archive: File::open(fixture.join("archive.tar")).unwrap(),
        commit: File::open(fixture.join("commit.object")).unwrap(),
    };
    let producer = InstalledProducer {
        python: fixture.join("python/bin/python3"),
        source: fixture.join("src"),
        purelib: fixture.join("purelib"),
        closure,
    };
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(unsafe { libc::setgroups(0, std::ptr::null()) }, 0);
    assert_eq!(unsafe { libc::setgid(1) }, 0);
    assert_eq!(unsafe { libc::setuid(1) }, 0);
    let (factory, operator, root, relay) = current_routed_fixture().await;
    let binding = super::super::owned_producer::GroupBinding::read(
        &factory.receiver.engine,
        &factory.receiver.group,
        &[7; 32],
    )
    .unwrap();
    assert_eq!(factory.receiver.group.as_slice().len(), 16);
    assert!(
        super::super::owned_producer::GroupBinding::read(
            &factory.receiver.engine,
            &factory.receiver.group,
            &[8; 32],
        )
        .is_err()
    );
    // Explicit test-only root fixture prepares its profile from this actual
    // Engine group's native identity. This handshake is not a deployment permit.
    std::fs::write(
        "/run/heterodyne-deploy-publication/group-request",
        hex::encode(factory.receiver.group.as_slice()),
    )
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new("/run/heterodyne-deploy-publication/profile-ready").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "bounded fixture root preparation"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let ask = producer
        .produce(inputs, &original, &binding)
        .expect("unchanged producer actual TLS/Git/render");
    assert_eq!(ask.expected_group, factory.receiver.group);
    let frame = qualify_owned_exchange(factory, operator, root, relay, ask).await;
    std::fs::write(
        "/run/heterodyne-deploy-publication/qualification-output.json",
        serde_json::to_vec(&serde_json::json!({
            "actual_unchanged_installed_producer": true,
            "actual_engine_native_routing_binding": true,
            "actual_mls_notification_eose_durable_consume_frame": true,
            "frame": frame,
            "installed_authority": false,
        }))
        .unwrap(),
    )
    .unwrap();
}

// Disposable capability qualification only; no receiver enrollment or network.
#[tokio::test]
async fn owned_routing_construction_preserves_default_refusals_and_accepts_current_welcome() {
    use cgka_traits::{
        app_components::{
            AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
        },
        engine::{CreateGroupRequest, SendResult},
        transport::TransportEnvelope,
    };
    fn client(
        storage: SqliteAccountStorage,
        keys: nostr::Keys,
        routing: bool,
    ) -> Engine<SqliteAccountStorage> {
        if routing {
            // This is the production constructor shared by both fixed entries.
            owned_routed_engine(
                storage,
                keys,
                crate::protected_capability_policy::routing_only_v1(),
            )
            .unwrap()
        } else {
            EngineBuilder::new(storage)
                .identity(keys.public_key().to_bytes().to_vec())
                .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
                .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(keys)))
                .build()
                .unwrap()
        }
    }
    // Both fresh-KeyPackage capability and join-time capability are varied.
    // Reopening the same in-memory storage retains the actual private KP state.
    for (creator_routing, kp_routing, join_routing) in [
        (false, true, true),
        (true, false, false),
        (true, true, false),
        (true, true, true),
    ] {
        let mut creator = client(
            SqliteAccountStorage::in_memory().unwrap(),
            nostr::Keys::generate(),
            creator_routing,
        );
        let keys = nostr::Keys::generate();
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let mut recipient = client(storage.clone(), keys.clone(), kp_routing);
        let mut kp = recipient.fresh_key_package().await.unwrap();
        kp.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::types::MessageId::new(vec![4; 32]),
        });
        drop(recipient);
        let mut recipient = client(storage.clone(), keys.clone(), join_routing);
        let result = creator
            .create_group(CreateGroupRequest {
                name: "disposable capability qualification".into(),
                description: String::new(),
                members: vec![kp],
                required_features: vec![],
                initial_admins: vec![],
                app_components: vec![AppComponentData {
                    component_id: NOSTR_ROUTING_COMPONENT_ID,
                    data: encode_nostr_routing_v1(
                        &NostrRoutingV1::new([7; 32], vec!["wss://semantic.invalid".into()])
                            .unwrap(),
                    )
                    .unwrap(),
                }],
            })
            .await;
        match result {
            Err(error) => {
                println!(
                    "creator={creator_routing} kp={kp_routing} join={join_routing}: create ERROR {error:?}"
                );
                assert!(
                    !creator_routing || !kp_routing,
                    "explicit-capability creation control must succeed"
                );
            }
            Ok((group, SendResult::FoundingGroupCreated { welcomes })) => {
                assert!(
                    creator_routing && kp_routing,
                    "default capabilities unexpectedly created routed group"
                );
                let welcome = welcomes.into_iter().find(|w| matches!(
                    &w.envelope, TransportEnvelope::Welcome { recipient: id } if id == &recipient.self_id()
                )).unwrap();
                let joined = recipient.join_welcome(welcome).await;
                println!(
                    "creator={creator_routing} kp={kp_routing} join={join_routing}: join {joined:?}"
                );
                assert_eq!(joined.is_ok(), join_routing);
                if join_routing {
                    assert!(
                        super::super::owned_producer::GroupBinding::read(
                            &recipient, &group, &[7; 32]
                        )
                        .is_ok()
                    );
                    drop(recipient);
                    // The resumed receiver uses the exact same constructor.
                    let reopened = owned_routed_engine(
                        storage,
                        keys,
                        crate::protected_capability_policy::routing_only_v1(),
                    )
                    .unwrap();
                    assert!(
                        super::super::owned_producer::GroupBinding::read(
                            &reopened, &group, &[7; 32]
                        )
                        .is_ok()
                    );
                }
            }
            Ok(_) => panic!("current profile must emit founding Welcome"),
        }
    }
}
