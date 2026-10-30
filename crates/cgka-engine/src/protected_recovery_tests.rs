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
