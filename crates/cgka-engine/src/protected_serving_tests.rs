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
        writeln!(client, "{req}").unwrap();
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
