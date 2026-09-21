//! Real encrypted database locks must survive private-file permission passes.
#![cfg(unix)]

use rusqlite::{Connection, ErrorCode};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage, SqliteJournalMode, SqliteStorageOptions};

fn connection(path: &Path) -> Connection {
    let db = Connection::open(path).unwrap();
    db.pragma_update(None, "key", format!("x'{}'", hex::encode([7; 32])))
        .unwrap();
    db.busy_timeout(Duration::ZERO).unwrap();
    let version: String = db
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .unwrap();
    assert!(!version.is_empty(), "test requires native SQLCipher");
    db
}

#[test]
fn encrypted_writer_child() {
    let Some(path) = std::env::var_os("MDK_LOCK_TEST_DB") else {
        return;
    };
    let db = connection(Path::new(&path));
    let result = db.execute_batch("BEGIN IMMEDIATE; INSERT INTO lock_probe VALUES (2); COMMIT;");
    if std::env::var("MDK_LOCK_TEST_EXPECT").unwrap() == "busy" {
        assert_eq!(
            result.unwrap_err().sqlite_error_code(),
            Some(ErrorCode::DatabaseBusy)
        );
    } else {
        result.unwrap();
    }
}

fn competing_writer(path: &Path, expected: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "encrypted_writer_child", "--nocapture"])
        .env("MDK_LOCK_TEST_DB", path)
        .env("MDK_LOCK_TEST_EXPECT", expected)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn preserves_writer_lock(journal_mode: SqliteJournalMode, commit: bool) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("encrypted.sqlite");
    let key = SqlCipherKey::new(format!("x'{}'", hex::encode([7; 32]))).unwrap();
    let options = SqliteStorageOptions {
        journal_mode,
        busy_timeout_ms: 0,
        ..Default::default()
    };
    // Two independent storage handles, not clones sharing a connection mutex.
    let first =
        SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone()).unwrap();
    let second =
        SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone()).unwrap();
    let db = connection(&path);
    db.execute_batch(
        "CREATE TABLE lock_probe (n INTEGER); BEGIN IMMEDIATE; INSERT INTO lock_probe VALUES (1);",
    )
    .unwrap();
    competing_writer(&path, "busy");
    for _ in 0..3 {
        fs_private::ensure_private_db_files(&path).unwrap();
        competing_writer(&path, "busy");
    }
    // A real storage opener also invokes the permission helper. Migrations
    // may report busy while our transaction is open; either outcome must
    // leave the first writer's exclusion intact, including on handle drop.
    drop(SqliteAccountStorage::open_encrypted_with_options(
        &path, &key, options,
    ));
    competing_writer(&path, "busy");
    assert!(!db.is_autocommit());
    db.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })
        .unwrap();
    competing_writer(&path, "success");
    let count: i64 = db
        .query_row("SELECT count(*) FROM lock_probe", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, if commit { 2 } else { 1 });
    let integrity: String = db
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    drop(db);
    second.close().unwrap();
    first.close().unwrap();
}

#[test]
fn encrypted_wal_writer_stays_exclusive_across_permission_passes_and_reopens() {
    preserves_writer_lock(SqliteJournalMode::Wal, true);
}

#[test]
fn encrypted_rollback_writer_stays_exclusive_across_permission_passes_and_reopens() {
    preserves_writer_lock(SqliteJournalMode::Delete, true);
}

#[test]
fn encrypted_wal_writer_becomes_available_after_rollback() {
    preserves_writer_lock(SqliteJournalMode::Wal, false);
}
