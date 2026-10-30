use super::*;
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};

fn open(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .unwrap()
}
fn files(root: &Path) -> OwnedFiles {
    let receiver = root.join("receiver");
    let consumer = root.join("consumer");
    std::fs::create_dir_all(&receiver).unwrap();
    std::fs::create_dir_all(&consumer).unwrap();
    OwnedFiles {
        journal: open(&receiver.join("journal")),
        journal_directory: File::open(&receiver).unwrap(),
        storage_lease: open(&receiver.join("storage-lease")),
        anchor: open(&consumer.join("anchor")),
        anchor_directory: File::open(&consumer).unwrap(),
    }
}
fn enrollment() -> Enrollment {
    Enrollment {
        account: "11".repeat(32),
        group: "22".repeat(32),
        operators: vec!["44".repeat(32), "33".repeat(32)],
        source_profile_sha256: "55".repeat(32),
        storage_generation: "66".repeat(32),
        initial_native_state_sha256: "77".repeat(32),
        welcome_provenance_sha256: "88".repeat(32),
    }
}
fn card(journal: &mut Journal) -> UseKey {
    journal
        .write(Body::CardComplete {
            ask_id: "ask3".into(),
            original_operation_sha256: "aa".repeat(32),
        })
        .unwrap();
    UseKey {
        header_sha256: journal.header_digest.clone(),
        card_complete_sequence: journal.sequence,
        ask_id: "ask3".into(),
        original_operation_sha256: "aa".repeat(32),
    }
}
#[test]
fn clean_published_unanswered_checkpoint_reopens_and_consumes_only_once_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    let key = card(&mut journal);
    drop(journal);
    let mut journal = Journal::reopen(files(root.path()), &enrollment()).unwrap();
    journal.write(Body::Consumed { key: key.clone() }).unwrap();
    drop(journal);
    let mut journal = Journal::reopen(files(root.path()), &enrollment()).unwrap();
    assert_eq!(
        journal.write(Body::Consumed { key }).unwrap_err(),
        Hold::Reused
    );
    assert!(!journal.latched);
}
#[test]
fn receiver_valid_prefix_restore_cannot_rollback_independent_consumer_one_use_anchor() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    let key = card(&mut journal);
    let before_use = std::fs::read(root.path().join("receiver/journal")).unwrap();
    journal.write(Body::Consumed { key }).unwrap();
    drop(journal);
    std::fs::write(root.path().join("receiver/journal"), before_use).unwrap();
    assert!(matches!(
        Journal::reopen(files(root.path()), &enrollment()),
        Err(Hold::Changed)
    ));
}
#[test]
fn deleted_interior_record_partial_line_and_anchor_suffix_each_hold() {
    for mode in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let mut journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
        let key = card(&mut journal);
        journal.write(Body::Consumed { key }).unwrap();
        drop(journal);
        let path = root.path().join(if mode == 2 {
            "consumer/anchor"
        } else {
            "receiver/journal"
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let changed = match mode {
            0 => content
                .lines()
                .enumerate()
                .filter(|(i, _)| *i != 1)
                .map(|(_, s)| format!("{s}\n"))
                .collect::<String>(),
            1 => content.trim_end_matches('\n').into(),
            _ => content.lines().take(2).map(|s| format!("{s}\n")).collect(),
        };
        std::fs::write(path, changed).unwrap();
        assert!(Journal::reopen(files(root.path()), &enrollment()).is_err());
    }
}
#[test]
fn duplicate_operator_rejected_and_order_is_canonical_but_changed_profile_holds() {
    let root = tempfile::tempdir().unwrap();
    let mut duplicate = enrollment();
    duplicate.operators.push(duplicate.operators[0].clone());
    assert!(matches!(
        Journal::enroll(files(root.path()), duplicate),
        Err(Hold::Changed)
    ));
    let journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    drop(journal);
    let mut reversed = enrollment();
    reversed.operators.reverse();
    let journal = Journal::reopen(files(root.path()), &reversed).unwrap();
    drop(journal);
    reversed.source_profile_sha256 = "ff".repeat(32);
    assert!(matches!(
        Journal::reopen(files(root.path()), &reversed),
        Err(Hold::Changed)
    ));
}
#[test]
fn second_independent_opener_and_same_inode_alias_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    assert!(matches!(
        Journal::reopen(files(root.path()), &enrollment()),
        Err(Hold::Lock)
    ));
    drop(journal);
    let mut aliased = files(root.path());
    aliased.anchor = open(&root.path().join("receiver/journal"));
    assert!(matches!(
        Journal::reopen(aliased, &enrollment()),
        Err(Hold::Changed)
    ));
}
#[test]
fn fresh_generation_and_wrong_card_scope_cannot_reuse_receipt() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let mut journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    let key = card(&mut journal);
    let mut fresh = Journal::enroll(files(other.path()), enrollment()).unwrap();
    card(&mut fresh);
    assert_ne!(journal.header_digest, fresh.header_digest);
    assert_eq!(
        fresh
            .write(Body::Consumed { key: key.clone() })
            .unwrap_err(),
        Hold::Changed
    );
    let mut wrong = key;
    wrong.original_operation_sha256 = "bb".repeat(32);
    assert_eq!(
        journal.write(Body::Consumed { key: wrong }).unwrap_err(),
        Hold::Changed
    );
}
#[test]
fn real_anchor_write_failure_retains_journal_suffix_and_latches_without_retry() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    // The already exclusively held consumer anchor is changed to a read-only
    // descriptor only in this fault fixture. No production injection API.
    let readonly = File::open(root.path().join("consumer/anchor")).unwrap();
    drop(std::mem::replace(&mut journal.files.anchor, readonly));
    let result = journal.write(Body::CardComplete {
        ask_id: "ask3".into(),
        original_operation_sha256: "aa".repeat(32),
    });
    assert_eq!(result.unwrap_err(), Hold::Io);
    assert_eq!(
        journal
            .write(Body::CardComplete {
                ask_id: "ask2".into(),
                original_operation_sha256: "aa".repeat(32),
            })
            .unwrap_err(),
        Hold::Latched
    );
    drop(journal);
    assert!(matches!(
        Journal::reopen(files(root.path()), &enrollment()),
        Err(Hold::Changed)
    ));
}
#[test]
fn duplicate_unknown_and_noncanonical_record_bytes_refuse_without_rewrite() {
    for extra in [",\"unexpected\":true", ",\"sequence\":1", " "] {
        let root = tempfile::tempdir().unwrap();
        drop(Journal::enroll(files(root.path()), enrollment()).unwrap());
        let path = root.path().join("receiver/journal");
        let content = std::fs::read_to_string(&path).unwrap();
        let bad = if extra == " " {
            format!(" {content}")
        } else {
            format!(
                "{}{}{}\n",
                content.trim_end().trim_end_matches('}'),
                extra,
                "}"
            )
        };
        std::fs::write(&path, &bad).unwrap();
        assert!(Journal::reopen(files(root.path()), &enrollment()).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), bad);
    }
}

#[test]
fn duplicate_card_identity_and_clock_rollback_refuse_before_any_write() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    card(&mut journal);
    let before = std::fs::read(root.path().join("receiver/journal")).unwrap();
    assert_eq!(
        journal
            .write(Body::CardComplete {
                ask_id: "ask3".into(),
                original_operation_sha256: "bb".repeat(32),
            })
            .unwrap_err(),
        Hold::Reused
    );
    journal.last_time = u64::MAX;
    assert_eq!(
        journal
            .write(Body::Transition {
                transition: TransitionKind::Outcome,
                payload_hex: "00".into(),
            })
            .unwrap_err(),
        Hold::Clock
    );
    assert_eq!(
        std::fs::read(root.path().join("receiver/journal")).unwrap(),
        before
    );
}
#[test]
fn streamed_history_crosses_former_lifetime_cap_and_reopens_without_authority_replay() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = Journal::enroll(files(root.path()), enrollment()).unwrap();
    for _ in 0..34 {
        journal
            .write(Body::Transition {
                transition: TransitionKind::Outcome,
                payload_hex: "ab".repeat(512 * 1024),
            })
            .unwrap();
    }
    assert!(journal.files.journal.metadata().unwrap().len() > 32 * 1024 * 1024);
    let sequence = journal.sequence;
    drop(journal);
    let mut journal = Journal::reopen(files(root.path()), &enrollment()).unwrap();
    assert_eq!(journal.sequence, sequence);
    let key = card(&mut journal);
    journal.write(Body::Consumed { key }).unwrap();
}
#[cfg(target_os = "linux")]
#[test]
fn actual_directory_fsync_failure_cannot_return_an_enrolled_owner_or_retry_header() {
    let root = tempfile::tempdir().unwrap();
    let mut handles = files(root.path());
    // procfs is an actual directory whose fsync returns EINVAL on Linux.
    handles.journal_directory = File::open("/proc").unwrap();
    assert!(matches!(
        Journal::enroll(handles, enrollment()),
        Err(Hold::Io)
    ));
    assert!(matches!(
        Journal::enroll(files(root.path()), enrollment()),
        Err(Hold::Changed)
    ));
}

/// Mechanical synthetic history fixture only. Uses actual journal/anchor fsync
/// and chain construction; it does not assert these synthetic MLS fields were
/// authenticated. Actual native causal tests qualify that separate boundary.
pub(crate) fn catalog_terminal_fixture(j: &mut Journal, index: u64, policy: &str) -> String {
    use cgka_traits::{
        app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent},
        transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource},
        types::{GroupId, MemberId, MessageId},
    };
    use serde_json::json;
    let alphabet = b"23456789abcdefghjkmnpqrstuvwxyz";
    let mut n = index;
    let mut id = String::new();
    for _ in 0..4 {
        id.push(alphabet[(n % alphabet.len() as u64) as usize] as char);
        n /= alphabet.len() as u64;
    }
    let group = GroupId::new(vec![0x22; 32]);
    let sender = MemberId::new(vec![0x33; 32]);
    let op = b"original operation";
    let original_sha = hex::encode(Sha256::digest(op));
    let received = now().unwrap();
    let mut source = |kind, value: serde_json::Value| {
        j.write(Body::Transition {
            transition: kind,
            payload_hex: hex::encode(serde_json::to_vec(&value).unwrap()),
        })
        .unwrap();
    };
    let appid = hex::encode(Sha256::digest(id.as_bytes()));
    let wire = TransportMessage {
        id: MessageId::new(hex::decode(&appid).unwrap()),
        payload: vec![0],
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mechanical-only".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group.as_slice().to_vec(),
        },
    };
    source(
        TransitionKind::Original,
        json!({"schema":"semantic-original.v2","original":{"ask_id":id,"expected_group":group,"operation":hex::encode(op),"operation_canonical":hex::encode(b"canonical"),"original_request":hex::encode(b"request"),"card_chunks":["x".repeat(1200)]},"policy_sha256":policy,"expires_at_unix_ms":received+60000}),
    );
    source(
        TransitionKind::Outbound,
        json!({"schema":"semantic-outbound.v1","ask_id":id,"part":0,"app_event_id":appid,"wire":wire}),
    );
    source(
        TransitionKind::Published,
        json!({"schema":"semantic-published.v1","ask_id":id,"part":0,"report":{"message_id":wire.id,"accepted":[{"endpoint":"wss://mechanical.invalid","accepted_at":null}],"failed":[],"required_acks":1}}),
    );
    source(
        TransitionKind::Published,
        json!({"schema":"semantic-card-complete.v1","ask_id":id,"app_ids":[appid],"policy_sha256":policy}),
    );
    // Mechanical reconstruction fixture only: unique IDs are generated above.
    // Avoid the production card_unused full-history lookup while generating
    // this large synthetic history. Exact record + independent anchor bytes,
    // hash chains and actual file/directory fsyncs still use production append.
    let mut record = Record {
        sequence: j.sequence + 1,
        previous_sha256: j.digest.clone(),
        local_unix_ms: now().unwrap(),
        body: Body::CardComplete {
            ask_id: id.clone(),
            original_operation_sha256: original_sha,
        },
        sha256: String::new(),
    };
    record.sha256 = record_digest(&record).unwrap();
    let mut anchor = Anchor {
        sequence: record.sequence,
        journal_sha256: record.sha256.clone(),
        previous_anchor_sha256: j.anchor_digest.clone(),
        use_key: None,
        sha256: String::new(),
    };
    anchor.sha256 = anchor_digest(&anchor).unwrap();
    append(&mut j.files.journal, &record).unwrap();
    append(&mut j.files.anchor, &anchor).unwrap();
    j.sequence = record.sequence;
    j.digest = record.sha256;
    j.anchor_digest = anchor.sha256;
    j.last_time = record.local_unix_ms;
    let app = MarmotAppEvent::new(
        hex::encode(sender.as_slice()),
        1700000000 + index,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        format!("!answer {id} no"),
    );
    let payload = app.encode().unwrap();
    let message_id = MessageId::new(Sha256::digest(&payload).to_vec());
    let incoming = TransportMessage {
        id: message_id.clone(),
        payload: payload.clone(),
        ..wire
    };
    let candidate = json!({"sequence":index+1,"received_at_unix_ms":received,"group":group,"message_id":hex::encode(message_id.as_slice()),"source_epoch":1,"sender":sender,"application":app});
    let mut source = |kind, value: serde_json::Value| {
        j.write(Body::Transition {
            transition: kind,
            payload_hex: hex::encode(serde_json::to_vec(&value).unwrap()),
        })
        .unwrap();
    };
    source(
        TransitionKind::Wire,
        json!({"schema":"receiver-wire.v1","sequence":index+1,"received_at_unix_ms":received,"wire":incoming}),
    );
    source(
        TransitionKind::Outcome,
        json!({"schema":"receiver-outcome.v1","sequence":index+1,"message_id":hex::encode(message_id.as_slice()),"outcome":cgka_traits::ingest::IngestOutcome::Processed,"candidate":candidate,"pending_application_ids":[message_id],"pending_application_projections":[{"group":group,"message_id":message_id,"sender":sender,"source_epoch":1,"payload_sha256":hex::encode(Sha256::digest(&payload)),"application_sha256":hex::encode(Sha256::digest(&payload))}],"native_merge":null}),
    );
    source(
        TransitionKind::Conflict,
        json!({"schema":"semantic-conflict.v1","ask_ids":[id],"authenticated_candidate":candidate}),
    );
    id
}

#[test]
fn consumed_export_key_is_native_anchored_generation_bound_and_survives_reopen() {
    let first = tempfile::tempdir().unwrap();
    let mut a = Journal::enroll(files(first.path()), enrollment()).unwrap();
    let old = card(&mut a);
    assert!(a.consumed_key("ask3", &"aa".repeat(32)).is_err());
    a.write(Body::Consumed { key: old.clone() }).unwrap();
    assert_eq!(a.consumed_key("ask3", &"aa".repeat(32)).unwrap(), old);
    drop(a);
    let a = Journal::reopen(files(first.path()), &enrollment()).unwrap();
    assert_eq!(a.consumed_key("ask3", &"aa".repeat(32)).unwrap(), old);
    let second = tempfile::tempdir().unwrap();
    let mut b = Journal::enroll(files(second.path()), enrollment()).unwrap();
    let current = card(&mut b);
    assert_ne!(current.header_sha256, old.header_sha256);
    assert_eq!(current.card_complete_sequence, old.card_complete_sequence);
    assert!(b.write(Body::Consumed { key: old }).is_err());
    assert!(b.consumed_key("ask3", &"aa".repeat(32)).is_err());
    b.write(Body::Consumed {
        key: current.clone(),
    })
    .unwrap();
    assert_eq!(b.consumed_key("ask3", &"aa".repeat(32)).unwrap(), current);
    assert!(b.consumed_key("ask3", &"bb".repeat(32)).is_err());
    assert!(b.write(Body::Consumed { key: current }).is_err());
    b.latched = true;
    assert!(b.consumed_key("ask3", &"aa".repeat(32)).is_err());
}
