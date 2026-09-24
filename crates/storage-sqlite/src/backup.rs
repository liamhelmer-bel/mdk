//! Consistent, keyed SQLCipher snapshots. The destination is never a plaintext
//! SQLite file, and callers only publish it after both native checks pass.
use crate::{IntegrityProbe, SqlCipherHardening, SqlCipherKey};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, ErrorCode, OpenFlags, backup::StepResult};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const BACKUP_PAGES_PER_STEP: i32 = 64;
const BUSY_PAUSE: Duration = Duration::from_millis(10);

/// Copy the account database through a separate, read-only keyed connection.
/// The SQLite online-backup API includes committed WAL pages in one consistent
/// image without monopolizing the live connection. A concurrent MLS write
/// invalidates the candidate at the app layer.
pub fn create_encrypted_backup(
    source: &Path,
    destination: &Path,
    key: &SqlCipherKey,
    budget: Duration,
    cancelled: &AtomicBool,
) -> StorageResult<IntegrityProbe> {
    if budget.is_zero() {
        return Ok(IntegrityProbe::Incomplete);
    }
    let started = Instant::now();
    let file = fs_private::create_new_private(destination)
        .map_err(|_| StorageError::Backend("create private backup failed".into()))?;
    drop(file);
    let from = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| StorageError::Backend("open backup source failed".into()))?;
    crate::open_hardened_sqlcipher(&from, key, SqlCipherHardening::cipher_only())?;
    let mut to = Connection::open_with_flags(
        destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| StorageError::Backend("open backup destination failed".into()))?;
    crate::open_hardened_sqlcipher(&to, key, SqlCipherHardening::cipher_only())?;
    {
        let backup = rusqlite::backup::Backup::new(&from, &mut to)
            .map_err(|_| StorageError::Backend("start encrypted backup failed".into()))?;
        loop {
            if cancelled.load(Ordering::Relaxed) || started.elapsed() >= budget {
                return Ok(IntegrityProbe::Incomplete);
            }
            match backup.step(BACKUP_PAGES_PER_STEP) {
                Ok(StepResult::Done) => break,
                Ok(StepResult::More) => {}
                Ok(StepResult::Busy | StepResult::Locked) => std::thread::sleep(BUSY_PAUSE),
                Err(_) => {
                    return Err(StorageError::Backend("encrypted backup copy failed".into()));
                }
                _ => {}
            }
        }
    }
    // The source runs in WAL mode. Make the destination a standalone file
    // before publication; a lone renamed main file must contain every page.
    let journal_mode: String = to
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .map_err(|_| StorageError::Backend("finalize encrypted backup failed".into()))?;
    if journal_mode != "delete" {
        return Err(StorageError::Backend(
            "encrypted backup remained in WAL mode".into(),
        ));
    }
    drop(to);
    Ok(verify_encrypted_backup(
        destination,
        key,
        budget.saturating_sub(started.elapsed()),
    ))
}

/// Check the backup itself, never the source connection. SQLCipher's cipher
/// check catches page authentication failures; SQLite's full integrity check
/// catches structural damage. Neither diagnostic row is exposed to logs.
pub fn verify_encrypted_backup(
    path: &Path,
    key: &SqlCipherKey,
    budget: Duration,
) -> IntegrityProbe {
    if budget.is_zero() {
        return IntegrityProbe::Incomplete;
    }
    let connection = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(connection) => connection,
        Err(_) => return IntegrityProbe::Incomplete,
    };
    if let Err(error) =
        crate::open_hardened_sqlcipher(&connection, key, SqlCipherHardening::cipher_only())
    {
        // Keyed-open failures are never considered healthy. The error mapping
        // does not preserve SQLite's code, so classify them conservatively.
        let _ = error;
        return IntegrityProbe::Corrupt;
    }
    let started = Instant::now();
    if connection
        .progress_handler(100, Some(move || started.elapsed() >= budget))
        .is_err()
    {
        return IntegrityProbe::Incomplete;
    }
    let check: Result<bool, rusqlite::Error> = (|| {
        let mut cipher = connection.prepare("PRAGMA cipher_integrity_check")?;
        let mut rows = cipher.query([])?;
        if rows.next()?.is_some() {
            return Ok(false);
        }
        let structural: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(structural == "ok")
    })();
    if connection
        .progress_handler(0, None::<fn() -> bool>)
        .is_err()
    {
        return IntegrityProbe::Incomplete;
    }
    match check {
        Ok(true) => IntegrityProbe::Healthy,
        Ok(false) => IntegrityProbe::Corrupt,
        Err(error) => match error.sqlite_error_code() {
            Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => IntegrityProbe::Corrupt,
            _ => IntegrityProbe::Incomplete,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_backup_requires_key_and_rejects_damaged_pages() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("session.sqlite");
        let destination = directory.path().join("backup.sqlite");
        let key = SqlCipherKey::new("test-only-key").unwrap();
        let store = crate::SqliteAccountStorage::open_encrypted(&source, &key).unwrap();
        store
            .lock()
            .unwrap()
            .execute_batch("CREATE TABLE backup_probe(value TEXT); INSERT INTO backup_probe VALUES ('secret marker');")
            .unwrap();
        assert_eq!(
            create_encrypted_backup(
                &source,
                &destination,
                &key,
                Duration::from_secs(5),
                &AtomicBool::new(false)
            )
            .unwrap(),
            IntegrityProbe::Healthy
        );
        let raw = std::fs::read(&destination).unwrap();
        assert!(!destination.with_extension("sqlite-wal").exists());
        assert!(!destination.with_extension("sqlite-shm").exists());
        assert!(!raw.starts_with(b"SQLite format 3"));
        assert!(
            !raw.windows(b"secret marker".len())
                .any(|w| w == b"secret marker")
        );
        assert_eq!(
            verify_encrypted_backup(
                &destination,
                &SqlCipherKey::new("wrong").unwrap(),
                Duration::from_secs(5)
            ),
            IntegrityProbe::Corrupt
        );
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&destination)
            .unwrap();
        file.seek(SeekFrom::Start(4096)).unwrap();
        file.write_all(&[0; 64]).unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            verify_encrypted_backup(&destination, &key, Duration::from_secs(5)),
            IntegrityProbe::Corrupt
        );
    }
}
