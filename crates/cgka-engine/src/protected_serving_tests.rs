//! Disposable actual native MLS fixtures. Relay acknowledgements are injected;
//! these tests do not claim installed process custody or live group enrollment.
use super::*;
use crate::Engine;
use std::os::unix::fs::PermissionsExt;

fn history(file: File) -> store::Store {
    store::Store::open(file, &"1".repeat(64), &"2".repeat(64)).unwrap()
}
fn profile(factory: &SemanticFactory<SqliteAccountStorage>) -> ServingProfile {
    ServingProfile {
        schema: "heterodyne-protected-receiver-serving.v1".into(),
        receiver_uid: unsafe { libc::geteuid() },
        hermes_uid: 12345,
        serving_generation: "1".repeat(64),
        enrollment: factory.ordered().unwrap().enrollment().unwrap(),
        endpoints: factory.endpoints.clone(),
        transport_group: vec![7; 32],
        // Dispatch tests never invoke installation verification. The actual
        // production entry always verifies its complete inherited installation.
        installation: receiver_installation_verifier::reference::Installation {
            root: "/unused-dispatch-fixture".into(),
            index_sha256: "0".repeat(64),
            recipe_id: "fixture".into(),
            platform_id: "fixture".into(),
        },
    }
}
fn request(p: &ServingProfile, key: &str, text: &str) -> Value {
    json!({"type":"send_final","id":"test","marmot_agent_control":PROTOCOL,
        "auth_token":"unused-dispatch-fixture","account_id_hex":p.enrollment.account,
        "group_id_hex":p.enrollment.group,"idempotency_key":key,"text":text})
}
#[test]
fn serving_store_reopens_exact_binding_and_preserves_uncertain_tail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history");
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut s = history(file);
    s.append(store::Record::Intent {
        key: "pending".into(),
        content: json!({"text":"retained"}),
        epoch: 3,
    })
    .unwrap();
    drop(s);
    let open = || {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap()
    };
    let s = history(open());
    assert!(s.outbound["pending"].prepared.is_none());
    drop(s);
    assert!(store::Store::open(open(), &"3".repeat(64), &"2".repeat(64)).is_err());
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"state\":")
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(store::Store::open(open(), &"1".repeat(64), &"2".repeat(64)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
#[tokio::test]
async fn serving_native_lost_ack_reuses_exact_wire_and_distinct_operations_remain_distinct() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    let (mut factory, mut operator, _root, relay) =
        super::super::whole_packet_qualification::current_routed_fixture().await;
    let p = profile(&factory);
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut h = history(file.reopen().unwrap());
    *relay.fail_at.lock().unwrap() = Some(1);
    let req = request(&p, "operation-a", "same text");
    assert!(
        dispatch(&mut factory, &p, &mut h, req.clone())
            .await
            .is_err()
    );
    assert!(!h.outbound["final:operation-a"].published);
    let saved =
        serde_json::to_vec(&h.outbound["final:operation-a"].prepared.as_ref().unwrap().1).unwrap();
    *relay.fail_at.lock().unwrap() = None;
    let ack = dispatch(&mut factory, &p, &mut h, req.clone())
        .await
        .unwrap();
    assert!(h.outbound["final:operation-a"].published);
    let wires = relay.wires.lock().unwrap().clone();
    assert_eq!(wires.len(), 2);
    assert_eq!(serde_json::to_vec(&wires[0]).unwrap(), saved);
    assert_eq!(serde_json::to_vec(&wires[1]).unwrap(), saved);
    operator.ingest(wires[1].clone()).await.unwrap();
    assert_eq!(dispatch(&mut factory, &p, &mut h, req).await.unwrap(), ack);
    assert_eq!(relay.wires.lock().unwrap().len(), 2);
    assert!(
        dispatch(
            &mut factory,
            &p,
            &mut h,
            request(&p, "operation-a", "changed")
        )
        .await
        .is_err()
    );
    let b = dispatch(
        &mut factory,
        &p,
        &mut h,
        request(&p, "operation-b", "same text"),
    )
    .await
    .unwrap();
    assert_ne!(ack["message_ids_hex"], b["message_ids_hex"]);
    assert_eq!(relay.wires.lock().unwrap().len(), 3);
    // Retained intent with no signed result is never reconstructed or re-signed.
    h.append(store::Record::Intent {
        key: "final:uncertain".into(),
        content: json!({"kind":MARMOT_APP_EVENT_KIND_CHAT,"text":"uncertain","tags":[]}),
        epoch: factory
            .receiver
            .engine
            .group_authority(&factory.receiver.group)
            .unwrap()
            .facts
            .epoch
            .0,
    })
    .unwrap();
    assert!(
        dispatch(
            &mut factory,
            &p,
            &mut h,
            request(&p, "uncertain", "uncertain")
        )
        .await
        .is_err()
    );
    assert_eq!(relay.wires.lock().unwrap().len(), 3);
}
async fn inbound(
    factory: &mut SemanticFactory<SqliteAccountStorage>,
    operator: &mut Engine<SqliteAccountStorage>,
    kind: u64,
    tags: Vec<Vec<String>>,
    text: &str,
) -> String {
    let event = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1234,
        kind,
        tags,
        text,
    );
    let result = operator
        .send(SendIntent::AppMessage {
            group_id: factory.receiver.group.clone(),
            payload: event.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let SendResult::ApplicationMessage { msg, .. } = result else {
        panic!("actual app message")
    };
    factory.ingest(msg).await.unwrap();
    event.id
}
#[tokio::test]
async fn serving_replay_requires_authenticated_native_journal_and_restores_reply_context() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    let (mut factory, mut operator, _root, _relay) =
        super::super::whole_packet_qualification::current_routed_fixture().await;
    let p = profile(&factory);
    let file = tempfile::NamedTempFile::new().unwrap();
    let h = history(file.reopen().unwrap());
    let id = inbound(
        &mut factory,
        &mut operator,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "original native text",
    )
    .await;
    let reply = inbound(
        &mut factory,
        &mut operator,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![vec!["e".into(), id.clone(), "".into(), "reply".into()]],
        "reply native text",
    )
    .await;
    let (events, last) = projection::replay(&factory, &p, &h, 0).unwrap();
    assert_eq!(events.len(), 2);
    assert!(last > 0);
    assert_eq!(events[0]["message"]["message_id_hex"], id);
    assert_eq!(events[1]["message"]["message_id_hex"], reply);
    assert_eq!(
        events[1]["reply_to"]["text_excerpt"],
        "original native text"
    );
    assert_eq!(
        events[1]["reply_to"]["sender"]["account_id_hex"],
        hex::encode(operator.self_id().as_slice())
    );
    assert_eq!(events[1]["serving_generation"], p.serving_generation);
    assert!(events[1]["source_epoch"].is_u64());
    assert!(events[1]["journal_cursor"].as_u64().unwrap() > 0);
    assert!(
        projection::replay(&factory, &p, &h, last)
            .unwrap()
            .0
            .is_empty()
    );
    assert_eq!(projection::replay(&factory, &p, &h, 0).unwrap().0, events);
    inbound(
        &mut factory,
        &mut operator,
        MARMOT_APP_EVENT_KIND_REACTION,
        vec![vec!["e".into(), id.clone()]],
        "👍",
    )
    .await;
    let (reactions, reaction_cursor) = projection::replay(&factory, &p, &h, last).unwrap();
    assert_eq!(reactions.len(), 1);
    assert_eq!(reactions[0]["type"], "reaction_added");
    assert_eq!(
        reactions[0]["target"]["text_excerpt"],
        "original native text"
    );
    assert!(reaction_cursor > last);
    // Retained fixture-only wire evidence for the real Hermes/Product decoder.
    let mut captured = events.clone();
    captured.extend(reactions.clone());
    for frame in &mut captured {
        frame["id"] = json!("native-serving-fixture");
        frame["marmot_agent_control"] = json!(PROTOCOL);
    }
    eprintln!(
        "SERVING_NATIVE_PROJECTION_FIXTURE={}",
        serde_json::to_string(&captured).unwrap()
    );
    let reaction = json!({"type":"send_reaction","id":"reaction","marmot_agent_control":PROTOCOL,"auth_token":"fixture","account_id_hex":p.enrollment.account,"group_id_hex":p.enrollment.group,"target_message_id_hex":id,"emoji":"👍"});
    let mut mutable_history = h;
    let reaction_ack = dispatch(&mut factory, &p, &mut mutable_history, reaction.clone())
        .await
        .unwrap();
    assert_eq!(
        dispatch(&mut factory, &p, &mut mutable_history, reaction)
            .await
            .unwrap(),
        reaction_ack
    );
    let mut wrong = profile(&factory);
    wrong.enrollment.group = "0".repeat(32);
    assert!(projection::replay(&factory, &wrong, &mutable_history, 0).is_err());
}
#[test]
fn serving_unix_channel_requires_peer_and_token_before_dispatch() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let run = |uid: u32, token: &str| {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let active = Arc::new(AtomicUsize::new(0));
        channel::spawn(server, uid, "a".repeat(64), tx, active);
        let req = json!({"id":"request-1","type":"group_info","marmot_agent_control":PROTOCOL,"auth_token":token});
        if let Err(error) = writeln!(client, "{req}") {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            return false; // Peer refusal may close before the request write.
        }
        if let Ok(Command::Call(call)) = rx.recv_timeout(Duration::from_secs(1)) {
            call.reply.send(Ok(json!({"type":"group_info"}))).unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["id"], "request-1");
            true
        } else {
            false
        }
    };
    let uid = unsafe { libc::geteuid() };
    assert!(run(uid, &"a".repeat(64)));
    assert!(!run(uid, &"b".repeat(64)));
    assert!(!run(uid + 1, &"a".repeat(64)));
}

#[test]
fn serving_channel_reports_only_recoverable_holds_as_retryable() {
    use std::io::{BufRead, BufReader, Write};
    for error in [
        ReceiverHold::Engine,
        ReceiverHold::Capacity,
        ReceiverHold::ChangedState,
        ReceiverHold::Journal,
        ReceiverHold::Latched,
        ReceiverHold::Malformed,
        ReceiverHold::Configuration,
    ] {
        let expected = matches!(error, ReceiverHold::Engine);
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        channel::spawn(
            server,
            unsafe { libc::geteuid() },
            "a".repeat(64),
            tx,
            Arc::new(AtomicUsize::new(0)),
        );
        writeln!(
            client,
            "{}",
            json!({"id":"retry-test", "type":"send_final",
            "marmot_agent_control":PROTOCOL,"auth_token":"a".repeat(64)})
        )
        .unwrap();
        let Command::Call(call) = rx.recv_timeout(Duration::from_secs(2)).unwrap() else {
            panic!("call")
        };
        call.reply.send(Err(error)).unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["retryable"], expected);
        assert_eq!(response["id"], "retry-test");
    }
}

#[tokio::test]
async fn serving_reopen_material_refuses_changes_before_reading_consumer_nonce() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    let (factory, _, _original_root, _) =
        super::super::whole_packet_qualification::current_routed_fixture().await;
    let mut enrollment = factory.ordered().unwrap().enrollment().unwrap();
    let keys = nostr::Keys::generate();
    enrollment.account = keys.public_key().to_hex();
    let root = tempfile::tempdir().unwrap();
    for name in ["anchor-dir", "journal-dir", "account-dir"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
        std::fs::set_permissions(
            root.path().join(name),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let key_path = root.path().join("key");
    let dbkey_path = root.path().join("dbkey");
    for (path, bytes) in [
        (&key_path, keys.secret_key().to_secret_bytes()),
        (&dbkey_path, [42; 32]),
    ] {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    let anchor_path = root.path().join("anchor-dir/fixed-anchor");
    let anchor = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&anchor_path)
        .unwrap();
    std::fs::set_permissions(&anchor_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let files = [
        File::open(&key_path).unwrap(),
        File::open(&dbkey_path).unwrap(),
        File::open("/dev/null").unwrap(),
        File::open(root.path().join("journal-dir")).unwrap(),
        File::open("/dev/null").unwrap(),
        anchor,
        File::open(root.path().join("anchor-dir")).unwrap(),
        File::open("/dev/null").unwrap(),
        File::open("/dev/null").unwrap(),
        File::open(root.path().join("account-dir")).unwrap(),
    ];
    for changed in ["key-length", "account-key", "directory", "anchor", "valid"] {
        let mut e = enrollment.clone();
        match changed {
            "key-length" => std::fs::write(&key_path, [1; 31]).unwrap(),
            "account-key" => e.account = "0".repeat(64),
            "directory" => std::fs::set_permissions(
                root.path().join("account-dir"),
                std::fs::Permissions::from_mode(0o750),
            )
            .unwrap(),
            "anchor" => {
                std::fs::set_permissions(&anchor_path, std::fs::Permissions::from_mode(0o640))
                    .unwrap()
            }
            _ => {}
        }
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut observation = receiver.try_clone().unwrap();
        observation
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        sender.write_all(&[77; 32]).unwrap();
        let receiver = unsafe { File::from_raw_fd(receiver.into_raw_fd()) };
        let result = consumer_startup(&e, unsafe { libc::geteuid() }, &files, receiver, unsafe {
            libc::geteuid()
        });
        if changed == "valid" {
            let (_, _peer, nonce) = result.unwrap();
            assert_eq!(nonce, [77; 32]);
            observation.set_nonblocking(true).unwrap();
            assert_eq!(
                observation.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        } else {
            assert!(result.is_err(), "{changed}");
            let mut untouched = [0; 32];
            observation.read_exact(&mut untouched).unwrap();
            assert_eq!(untouched, [77; 32], "{changed}");
        }
        std::fs::write(&key_path, keys.secret_key().to_secret_bytes()).unwrap();
        std::fs::set_permissions(
            root.path().join("account-dir"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&anchor_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn serving_foreign_peer_is_refused_without_waiting_for_request_bytes() {
    use std::io::Read;
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    channel::spawn(
        server,
        unsafe { libc::geteuid() } + 1,
        "a".repeat(64),
        tx,
        Arc::new(AtomicUsize::new(0)),
    );
    // No request or newline is sent. The kernel peer check must precede read.
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
}

#[test]
fn serving_listener_requires_actual_root_creator() {
    use std::os::fd::IntoRawFd;
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("socket")).unwrap();
    let file = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
    assert_eq!(
        channel::check_listener(&file).is_ok(),
        unsafe { libc::geteuid() } == 0
    );
    if unsafe { libc::geteuid() } != 0 {
        // Execute the same actual listener control in the existing disposable
        // mapped-root fixture, without claiming a production installation.
        assert!(!crate::protected_recovery::root_expiry_fixture_available());
    }
}

#[tokio::test]
async fn serving_native_uncertainty_and_retained_replay_refusal_stop_owner() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    let (mut factory, _, _root, _) =
        super::super::whole_packet_qualification::current_routed_fixture().await;
    // The native owner has latched an in-flight prepare. A transport Engine
    // error must not escape as retryable while the owner continues serving.
    factory.held = true;
    let (tx, rx) = mpsc::sync_channel(1);
    assert!(finish_call(&factory, tx, Err(ReceiverHold::Engine)).is_err());
    assert!(matches!(rx.recv().unwrap(), Err(ReceiverHold::Latched)));
    factory.held = false;
    let (tx, rx) = mpsc::sync_channel(1);
    assert!(finish_call(&factory, tx, Err(ReceiverHold::Engine)).is_ok());
    assert!(matches!(rx.recv().unwrap(), Err(ReceiverHold::Engine)));
    for error in [
        ReceiverHold::Journal,
        ReceiverHold::ChangedState,
        ReceiverHold::Capacity,
    ] {
        let (tx, rx) = mpsc::sync_channel(1);
        assert!(finish_replay(tx, Err(error)).is_err());
        assert!(rx.recv().unwrap().is_err());
    }
    let (tx, rx) = mpsc::sync_channel(1);
    assert!(finish_replay(tx, Ok((vec![], 0))).is_ok());
    assert!(rx.recv().unwrap().is_ok());
}

#[tokio::test]
async fn serving_actual_sdk_activation_requires_inbox_relays() {
    use transport_nostr_adapter::NostrSdkRelayClient;
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    let (factory, _operator, _root, _relay) =
        super::super::whole_packet_qualification::current_routed_fixture().await;
    let mut p = profile(&factory);
    // A bound loopback socket supplies a finite local relay address. This
    // qualifies SDK subscription registration, not relay delivery or TLS.
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    p.endpoints = vec![TransportEndpoint(format!(
        "ws://{}",
        socket.local_addr().unwrap()
    ))];
    let account = factory.receiver.engine.self_id();
    let group = factory.receiver.group.clone();
    let client = nostr_sdk::Client::builder().build();
    let sdk = NostrSdkRelayClient::new(client.clone());
    let adapter = NostrTransportAdapter::new(Arc::new(sdk.clone()));
    let mut broken = activation(&p, account.clone(), group.clone());
    broken.inbox_endpoints.clear();
    let error = tokio::time::timeout(Duration::from_secs(5), adapter.activate_account(broken))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, cgka_traits::TransportAdapterError::Subscription(_)),
        "{error:?}"
    );
    eprintln!("empty-inbox actual SDK refusal: {error}");
    tokio::time::timeout(
        Duration::from_secs(5),
        adapter.activate_account(activation(&p, account, group)),
    )
    .await
    .unwrap()
    .unwrap();
    client.shutdown().await;
}

#[tokio::test]
async fn serving_deferred_cipher_preserves_barrier_and_projects_next_native_chat() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    use cgka_traits::MessageStorage;
    use nostr::{EventBuilder, Kind, Tag, TagKind};
    let (mut factory, mut operator, root, relay) =
        super::super::super::tests::fresh_recovery_factory().await;
    factory = super::super::super::tests::restart_factory_for_mode(
        factory,
        root.path(),
        relay.clone(),
        "chat-entry-reopen",
        CONVERSATION_MODE,
    )
    .await
    .unwrap();
    assert!(!factory.receiver.authority_available());
    assert!(!factory.receiver.authority_blocked);
    let p = profile(&factory);
    let file = tempfile::NamedTempFile::new().unwrap();
    let h = history(file.reopen().unwrap());
    let app = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1234,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "actual chat after unresolved ciphertext",
    );
    let SendResult::ApplicationMessage { msg: valid, .. } = operator
        .send(SendIntent::AppMessage {
            group_id: factory.receiver.group.clone(),
            payload: app.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("actual native app message")
    };
    let envelope: Value = serde_json::from_slice(&valid.payload).unwrap();
    let route = envelope["tags"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t[0] == "h")
        .unwrap()[1]
        .as_str()
        .unwrap();
    let outer = EventBuilder::new(
        Kind::MlsGroupMessage,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .tags([Tag::custom(TagKind::custom("h"), [route])])
    .sign_with_keys(&nostr::Keys::generate())
    .unwrap();
    let unresolved = transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&outer)
        .unwrap()
        .to_transport_message()
        .unwrap();
    assert!(factory.ingest(unresolved.clone()).await.unwrap().is_none());
    assert!(factory.receiver.authority_blocked);
    assert!(!factory.held && !factory.receiver.latched);
    // Reopen the actual persisted native account and protected journal. No row
    // is deleted or relabelled Processed to make this continuation pass.
    factory = super::super::super::tests::restart_factory(
        factory,
        root.path(),
        relay.clone(),
        "chat-deferred-reopen",
    )
    .await
    .unwrap();
    assert!(factory.receiver.authority_blocked);
    assert!(!factory.receiver.authority_available());
    assert!(!factory.held && !factory.receiver.latched);
    let (before, cursor) = projection::replay(&factory, &p, &h, 0).unwrap();
    assert!(before.is_empty());
    factory.ingest(valid).await.unwrap();
    let (after, _) = projection::replay(&factory, &p, &h, cursor).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0]["type"], "inbound_message");
    assert_eq!(after[0]["message"]["message_id_hex"], app.id);
    assert_eq!(after[0]["message"]["text"], app.content);
    assert!(factory.receiver.authority_blocked);
    assert!(matches!(
        factory.consume("no-authority", &"0".repeat(64)),
        Err(ReceiverHold::Latched)
    ));
    assert_eq!(
        factory
            .receiver
            .engine
            .storage
            .get_message(&unresolved.id)
            .unwrap()
            .state,
        cgka_traits::message::MessageState::PeelDeferred
    );
    let mut cursor = factory.ordered().unwrap().source_cursor().unwrap();
    let mut retained_deferred = 0;
    while let Some(record) = cursor.next().unwrap() {
        let v = &record.body["value"];
        if v["schema"] == "receiver-outcome.v1" {
            let outcome: crate::protected_receiver::RetainedOutcome =
                serde_json::from_value(v.clone()).unwrap();
            if matches!(
                outcome.outcome,
                cgka_traits::ingest::IngestOutcome::TransportDeferred { .. }
            ) {
                assert!(outcome.candidate.is_none());
                assert!(outcome.pending_application_ids.is_empty());
                retained_deferred += 1;
            }
        }
    }
    assert_eq!(retained_deferred, 1);
}

#[tokio::test]
async fn conversation_catalog_accepts_edits_removals_and_relevant_replies_live_and_on_reopen() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    use cgka_traits::app_event::{
        MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_REACTION,
        MARMOT_APP_EVENT_KIND_REMOVE,
    };
    let (mut factory, mut operator, root, relay) =
        super::super::super::tests::fresh_recovery_factory().await;
    // Genuine retained ask predates this conversation-only incarnation.
    let ask = super::super::super::tests::finite_original("ask3", &factory.receiver.group);
    factory.post(ask.clone()).await.unwrap();
    let target = factory.asks["ask3"].app_ids[0].clone();
    factory = super::super::super::tests::restart_factory_for_mode(
        factory,
        root.path(),
        relay.clone(),
        "semantic-chat-entry",
        CONVERSATION_MODE,
    )
    .await
    .unwrap();
    for (index, (kind, text)) in [
        (MARMOT_APP_EVENT_KIND_EDIT, "edited"),
        (MARMOT_APP_EVENT_KIND_DELETE, ""),
        (MARMOT_APP_EVENT_KIND_REMOVE, ""),
        (MARMOT_APP_EVENT_KIND_CHAT, "!answer ask3 A"),
        (MARMOT_APP_EVENT_KIND_REACTION, "👍"),
    ]
    .into_iter()
    .enumerate()
    {
        let app = MarmotAppEvent::new(
            hex::encode(operator.self_id().as_slice()),
            1234 + index as u64,
            kind,
            vec![vec!["e".into(), target.clone()]],
            text,
        );
        let SendResult::ApplicationMessage { msg: wire, .. } = operator
            .send(SendIntent::AppMessage {
                group_id: factory.receiver.group.clone(),
                payload: app.encode().unwrap(),
                expected_epoch: None,
            })
            .await
            .unwrap()
        else {
            panic!("actual native app message")
        };
        assert!(factory.ingest(wire).await.unwrap().is_none());
        assert!(!factory.held && !factory.receiver.latched);
        factory = super::super::super::tests::restart_factory(
            factory,
            root.path(),
            relay.clone(),
            &format!("semantic-chat-reopen-{index}"),
        )
        .await
        .unwrap();
        assert!(!factory.receiver.authority_available());
        assert!(
            factory
                .asks
                .values()
                .all(|ask| ask.receipt.is_none() && !ask.consumed)
        );
        assert!(matches!(
            factory.consume("ask3", &super::super::super::digest(&ask.operation)),
            Err(ReceiverHold::Latched)
        ));
    }
    // Actual journal/native restart with a candidate retained at native ingress,
    // before live catalog projection. Reopen must not classify it into semantics.
    let app = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1240,
        MARMOT_APP_EVENT_KIND_EDIT,
        vec![vec!["e".into(), target]],
        "interrupted edit",
    );
    let SendResult::ApplicationMessage { msg: wire, .. } = operator
        .send(SendIntent::AppMessage {
            group_id: factory.receiver.group.clone(),
            payload: app.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("actual native app message")
    };
    factory.receiver.ingest(wire).await.unwrap();
    let sequence = factory.ordered().unwrap().checkpoint().0;
    factory = super::super::super::tests::restart_factory(
        factory,
        root.path(),
        relay,
        "semantic-chat-unprojected-reopen",
    )
    .await
    .unwrap();
    assert_eq!(factory.ordered().unwrap().checkpoint().0, sequence);
    assert!(!factory.held && !factory.receiver.latched);
    assert!(!factory.receiver.authority_available());
    assert!(
        factory
            .asks
            .values()
            .all(|ask| ask.receipt.is_none() && !ask.consumed)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn conversation_seal_refuses_authority_reopen_before_classifying_chat() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_REACTION};
    for kind in [MARMOT_APP_EVENT_KIND_REACTION, MARMOT_APP_EVENT_KIND_EDIT] {
        let (mut factory, mut operator, root, relay) =
            super::super::super::tests::fresh_recovery_factory().await;
        let ask = super::super::super::tests::finite_original("ask3", &factory.receiver.group);
        factory.post(ask).await.unwrap();
        let target = factory.asks["ask3"].app_ids[0].clone();
        factory = super::super::super::tests::restart_factory_for_mode(
            factory,
            root.path(),
            relay.clone(),
            "sealed-chat-entry",
            CONVERSATION_MODE,
        )
        .await
        .unwrap();
        let seal = factory.ordered().unwrap().conversation_seal();
        let mut cursor = factory.ordered().unwrap().source_cursor().unwrap();
        let mut seals = 0;
        while let Some(record) = cursor.next().unwrap() {
            if record.body["value"] == seal {
                seals += 1;
            }
        }
        assert_eq!(seals, 1);
        drop(cursor);
        let app = MarmotAppEvent::new(
            hex::encode(operator.self_id().as_slice()),
            1300,
            kind,
            vec![vec!["e".into(), target]],
            if kind == MARMOT_APP_EVENT_KIND_REACTION {
                "👍"
            } else {
                "edited"
            },
        );
        let SendResult::ApplicationMessage { msg: wire, .. } = operator
            .send(SendIntent::AppMessage {
                group_id: factory.receiver.group.clone(),
                payload: app.encode().unwrap(),
                expected_epoch: None,
            })
            .await
            .unwrap()
        else {
            panic!("actual native app message")
        };
        assert!(factory.ingest(wire).await.unwrap().is_none());
        factory = super::super::super::tests::restart_factory(
            factory,
            root.path(),
            relay.clone(),
            "sealed-chat-reopen",
        )
        .await
        .unwrap();
        assert!(!factory.receiver.authority_available());
        assert!(
            factory
                .asks
                .values()
                .all(|ask| ask.receipt.is_none() && !ask.consumed)
        );
        let journal = std::fs::read(root.path().join("receiver/journal")).unwrap();
        let anchor = std::fs::read(root.path().join("consumer/anchor")).unwrap();
        let result = super::super::super::tests::restart_factory_for_mode(
            factory,
            root.path(),
            relay,
            "forbidden-authority-reopen",
            super::super::super::super::ReceiverMode::Authority,
        )
        .await;
        assert!(matches!(result, Err(ReceiverHold::ChangedState)));
        assert_eq!(
            std::fs::read(root.path().join("receiver/journal")).unwrap(),
            journal
        );
        assert_eq!(
            std::fs::read(root.path().join("consumer/anchor")).unwrap(),
            anchor
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_conversation_reopen_keeps_unfinished_wire_unsealed_and_unchanged() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    use nostr::{EventBuilder, Kind, Tag, TagKind};
    let (mut factory, mut operator, root, relay) =
        super::super::super::tests::fresh_recovery_factory().await;
    let app = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1400,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "route fixture",
    );
    let SendResult::ApplicationMessage { msg: valid, .. } = operator
        .send(SendIntent::AppMessage {
            group_id: factory.receiver.group.clone(),
            payload: app.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("native message")
    };
    let envelope: Value = serde_json::from_slice(&valid.payload).unwrap();
    let route = envelope["tags"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t[0] == "h")
        .unwrap()[1]
        .as_str()
        .unwrap();
    let outer = EventBuilder::new(
        Kind::MlsGroupMessage,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .tags([Tag::custom(TagKind::custom("h"), [route])])
    .sign_with_keys(&nostr::Keys::generate())
    .unwrap();
    let wire = transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&outer)
        .unwrap()
        .to_transport_message()
        .unwrap();
    // Reproduce an actual interrupted old ingress: protected wire is durable,
    // native engine retains PeelDeferred, but no receiver outcome was written.
    factory
        .receiver
        .record(
            serde_json::json!({"schema":"receiver-wire.v1", "sequence":1,
        "received_at_unix_ms":factory.receiver.checked_now().unwrap(), "wire":wire}),
        )
        .unwrap();
    assert!(matches!(
        factory.receiver.engine.ingest(wire).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::TransportDeferred { .. }
    ));
    let journal = std::fs::read(root.path().join("receiver/journal")).unwrap();
    let anchor = std::fs::read(root.path().join("consumer/anchor")).unwrap();
    let result = super::super::super::tests::restart_factory_for_mode(
        factory,
        root.path(),
        relay,
        "failed-unfinished-chat",
        CONVERSATION_MODE,
    )
    .await;
    assert!(matches!(result, Err(ReceiverHold::ChangedState)));
    assert_eq!(
        std::fs::read(root.path().join("receiver/journal")).unwrap(),
        journal
    );
    assert_eq!(
        std::fs::read(root.path().join("consumer/anchor")).unwrap(),
        anchor
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_conversation_transport_binding_keeps_source_unsealed_and_unchanged() {
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    let (factory, _, root, relay) = super::super::super::tests::fresh_recovery_factory().await;
    let journal = std::fs::read(root.path().join("receiver/journal")).unwrap();
    let anchor = std::fs::read(root.path().join("consumer/anchor")).unwrap();
    let result = super::super::super::tests::restart_factory_for_mode_and_transport(
        factory,
        root.path(),
        relay,
        "failed-transport-binding",
        CONVERSATION_MODE,
        vec![8; 32],
    )
    .await;
    assert!(matches!(result, Err(ReceiverHold::ChangedState)));
    assert_eq!(
        std::fs::read(root.path().join("receiver/journal")).unwrap(),
        journal
    );
    assert_eq!(
        std::fs::read(root.path().join("consumer/anchor")).unwrap(),
        anchor
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn conversation_genuine_future_epoch_retains_while_new_chat_continues() {
    use cgka_traits::storage::MessageStorage;
    if !crate::protected_recovery::root_expiry_fixture_available() {
        return;
    }
    let (factory, mut operator, root, relay) =
        super::super::super::tests::fresh_recovery_factory().await;
    let mut factory = super::super::super::tests::restart_factory_for_mode(
        factory,
        root.path(),
        relay.clone(),
        "early-epoch",
        CONVERSATION_MODE,
    )
    .await
    .unwrap();
    let SendResult::GroupEvolution {
        msg: commit,
        pending,
        ..
    } = operator
        .send(SendIntent::SelfUpdate {
            group_id: factory.receiver.group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("native update")
    };
    operator.confirm_published(pending).await.unwrap();
    let early_app = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1500,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "future epoch member",
    );
    let SendResult::ApplicationMessage { msg: early, .. } = operator
        .send(SendIntent::AppMessage {
            group_id: factory.receiver.group.clone(),
            payload: early_app.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("actual future epoch message")
    };
    assert!(factory.ingest(early.clone()).await.unwrap().is_none());
    assert_eq!(
        factory
            .receiver
            .engine
            .storage
            .get_message(&early.id)
            .unwrap()
            .state,
        cgka_traits::message::MessageState::PeelDeferred
    );
    let retained_deferred = |factory: &SemanticFactory<SqliteAccountStorage>| {
        let mut source = factory.ordered().unwrap().source_cursor().unwrap();
        let mut count = 0;
        while let Some(record) = source.next().unwrap() {
            let value = &record.body["value"];
            if value["schema"] == "receiver-outcome.v1" {
                let outcome: crate::protected_receiver::RetainedOutcome =
                    serde_json::from_value(value.clone()).unwrap();
                if outcome.message_id == hex::encode(early.id.as_slice())
                    && outcome.is_opaque_deferred_for(&factory.receiver.group)
                {
                    count += 1;
                }
            }
        }
        count
    };
    assert_eq!(retained_deferred(&factory), 1);
    // Actual owned SDK ingress is Engine::ingest, not the general app runtime's
    // separate advance_convergence drain. The real update changes epoch but
    // leaves this original row PeelDeferred; no old-ID event is emitted here.
    assert!(factory.ingest(commit).await.unwrap().is_none());
    assert!(!factory.held && !factory.receiver.latched);
    assert_eq!(
        factory
            .receiver
            .engine
            .storage
            .get_message(&early.id)
            .unwrap()
            .state,
        cgka_traits::message::MessageState::PeelDeferred
    );
    assert_eq!(retained_deferred(&factory), 1);
    let history_file = tempfile::NamedTempFile::new().unwrap();
    let h = history(history_file.reopen().unwrap());
    let (before_redelivery, _) = projection::replay(&factory, &profile(&factory), &h, 0).unwrap();
    assert!(before_redelivery.is_empty(), "{before_redelivery:?}");
    factory = super::super::super::tests::restart_factory(
        factory,
        root.path(),
        relay.clone(),
        "after-native-update",
    )
    .await
    .unwrap();
    // Exact relay redelivery retains a NEW ingress/content binding and can
    // project the genuine early application without rewriting its original
    // native PeelDeferred row or its retained opaque Deferred outcome.
    assert!(factory.ingest(early.clone()).await.unwrap().is_none());
    assert_eq!(
        factory
            .receiver
            .engine
            .storage
            .get_message(&early.id)
            .unwrap()
            .state,
        cgka_traits::message::MessageState::PeelDeferred
    );
    let (redelivered, _) = projection::replay(&factory, &profile(&factory), &h, 0).unwrap();
    assert_eq!(redelivered.len(), 1);
    assert_eq!(redelivered[0]["message"]["message_id_hex"], early_app.id);
    assert_eq!(redelivered[0]["message"]["text"], early_app.content);
    let app = MarmotAppEvent::new(
        hex::encode(operator.self_id().as_slice()),
        1501,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "new chat after commit",
    );
    let SendResult::ApplicationMessage { msg: later, .. } = operator
        .send(SendIntent::AppMessage {
            group_id: factory.receiver.group.clone(),
            payload: app.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
    else {
        panic!("native later chat")
    };
    assert!(factory.ingest(later).await.unwrap().is_none());
    assert_eq!(retained_deferred(&factory), 1);
    assert!(factory.receiver.authority_blocked);
    assert!(!factory.receiver.authority_available());
    let file = tempfile::NamedTempFile::new().unwrap();
    let h = history(file.reopen().unwrap());
    let (messages, _) = projection::replay(&factory, &profile(&factory), &h, 0).unwrap();
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert_eq!(messages[0]["message"]["message_id_hex"], early_app.id);
    assert_eq!(messages[0]["message"]["text"], early_app.content);
    assert_eq!(messages[1]["message"]["message_id_hex"], app.id);
    assert_eq!(messages[1]["message"]["text"], app.content);
    factory = super::super::super::tests::restart_factory(
        factory,
        root.path(),
        relay,
        "after-genuine-redelivery",
    )
    .await
    .unwrap();
    assert!(!factory.held && !factory.receiver.latched);
    assert!(!factory.receiver.authority_available());
    assert_eq!(retained_deferred(&factory), 1);
    let (reopened, _) = projection::replay(&factory, &profile(&factory), &h, 0).unwrap();
    assert_eq!(reopened, messages);
}
