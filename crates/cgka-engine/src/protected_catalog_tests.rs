use super::*;
use crate::protected_recovery::{Enrollment, OwnedFiles};
use std::{os::unix::fs::DirBuilderExt, path::Path};
fn files(root: &Path) -> OwnedFiles {
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
    OwnedFiles {
        journal: open(receiver.join("journal")),
        journal_directory: File::open(&receiver).unwrap(),
        storage_lease: open(receiver.join("lease")),
        anchor: open(consumer.join("anchor")),
        anchor_directory: File::open(&consumer).unwrap(),
    }
}
#[test]
#[ignore = "explicit long-running anchored fsync history qualification"]
fn terminal_history_above_ten_thousand_and_32mib_rebuilds_with_bounded_live_projection() {
    let root = tempfile::tempdir().unwrap();
    let enrollment = Enrollment {
        schema: "heterodyne-receiver-enrollment.v3".into(),
        expiry_profile_sha256: "66".repeat(32),
        installation_index_sha256: "aa".repeat(32),
        installation_source_sha256: "bb".repeat(32),
        capability_template: crate::protected_capability_policy::routing_only_v1()
            .id()
            .into(),
        capability_policy_sha256: crate::protected_capability_policy::routing_only_v1()
            .policy_sha256(),
        account: "11".repeat(32),
        group: "22".repeat(32),
        operators: vec!["33".repeat(32)],
        source_profile_sha256: "44".repeat(32),
        storage_generation: "55".repeat(32),
        initial_native_state_sha256: "66".repeat(32),
        welcome_provenance_sha256: "77".repeat(32),
    };
    let policy = "88".repeat(32);
    let mut journal = Journal::enroll(files(root.path()), enrollment.clone()).unwrap();
    let mut last = String::new();
    for i in 0..10001 {
        last = crate::protected_recovery::tests::catalog_terminal_fixture(&mut journal, i, &policy);
    }
    assert!(journal.length().unwrap() > 32 * 1024 * 1024);
    drop(journal);
    let journal = Journal::reopen(files(root.path()), &enrollment).unwrap();
    let path = root.path().join("cache");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    let catalog = Catalog::rebuild(
        &journal,
        File::open(&path).unwrap(),
        &policy,
        &[TransportEndpoint::from("wss://mechanical.invalid")],
    )
    .unwrap();
    assert!(catalog.unanswered.is_empty());
    assert_eq!(catalog.high_water_unanswered, 1);
    assert_eq!(catalog.receiver_sequence, 10001);
    assert_eq!(
        catalog.ask(&journal, &last).unwrap().unwrap().disposition,
        Disposition::Conflicted
    );
    assert_eq!(
        catalog.ask(&journal, "2222").unwrap().unwrap().disposition,
        Disposition::Conflicted
    );
    assert!(
        Catalog::rebuild(
            &journal,
            File::open(&path).unwrap(),
            &policy,
            &[TransportEndpoint::from("wss://mechanical.invalid")]
        )
        .is_err()
    );
}

#[test]
fn cache_read_and_write_refuse_symlink_without_touching_target() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("cache");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let disk = Disk::fresh(File::open(&directory).unwrap()).unwrap();
    let target = root.path().join("untouched");
    std::fs::write(&target, b"retained original").unwrap();
    symlink(&target, disk.key(Space::Checkpoint, "key")).unwrap();
    assert!(
        disk.read::<serde_json::Value>(Space::Checkpoint, "key")
            .is_err()
    );
    assert!(
        disk.put(
            Space::Checkpoint,
            "key",
            &serde_json::json!({"replacement":true})
        )
        .is_err()
    );
    assert_eq!(std::fs::read(target).unwrap(), b"retained original");
}
