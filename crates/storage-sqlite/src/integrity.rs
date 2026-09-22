//! Privacy-safe, read-only structural checks on the existing keyed connection.
use crate::SqliteAccountStorage;
use cgka_traits::storage::StorageResult;
use std::time::{Duration, Instant};

/// A completed check is distinct from a probe that could not finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityProbe {
    Healthy,
    Corrupt,
    Incomplete,
}

impl SqliteAccountStorage {
    /// Check SQLite structure without exposing diagnostic rows (which can contain
    /// private values). This is not a full index/foreign-key or MLS semantic audit.
    /// The budget interrupts SQLite VM work; connection waits and filesystem I/O
    /// are not preemptible. No migrations, new connections, or repair are performed.
    pub fn probe_integrity(&self, budget: Duration) -> StorageResult<IntegrityProbe> {
        let connection = self.lock()?;
        let result = probe(&connection, budget);
        if result == IntegrityProbe::Corrupt {
            connection.record_integrity_failure();
        }
        Ok(result)
    }
}

fn probe(connection: &rusqlite::Connection, budget: Duration) -> IntegrityProbe {
    if budget.is_zero() {
        return IntegrityProbe::Incomplete;
    }
    let started = Instant::now();
    if connection
        .progress_handler(100, Some(move || started.elapsed() >= budget))
        .is_err()
    {
        return IntegrityProbe::Incomplete;
    }
    let result = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0));
    // Clear the connection-local callback even when SQLite rejects the query.
    if connection
        .progress_handler(0, None::<fn() -> bool>)
        .is_err()
    {
        return IntegrityProbe::Incomplete;
    }
    match result {
        Ok(result) if result == "ok" => IntegrityProbe::Healthy,
        Ok(_) => IntegrityProbe::Corrupt,
        Err(error) => match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase) => {
                IntegrityProbe::Corrupt
            }
            _ => IntegrityProbe::Incomplete,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_probe_captures_structural_failure_but_not_healthy_or_incomplete() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session.sqlite");
        let key = crate::SqlCipherKey::new("probe-fixture-key").unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let artifact = directory.path().join("session.sqlite.forensics.json");
        assert_eq!(
            storage.probe_integrity(Duration::ZERO).unwrap(),
            IntegrityProbe::Incomplete
        );
        assert_eq!(
            storage.probe_integrity(Duration::from_secs(2)).unwrap(),
            IntegrityProbe::Healthy
        );
        assert!(!artifact.exists());
        storage.lock().unwrap().execute_batch("CREATE TABLE probe_sample(value TEXT CHECK(length(value) < 2)); PRAGMA ignore_check_constraints=ON; INSERT INTO probe_sample VALUES ('PRIVATE_PROBE_SENTINEL'); PRAGMA ignore_check_constraints=OFF;").unwrap();
        assert_eq!(
            storage.probe_integrity(Duration::from_secs(2)).unwrap(),
            IntegrityProbe::Corrupt
        );
        let bytes = std::fs::read(&artifact).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            record["sqlite_extended_code"],
            rusqlite::ffi::SQLITE_CORRUPT
        );
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("PRIVATE_PROBE_SENTINEL")
        );
        storage.close().unwrap();
    }

    #[test]
    fn damaged_encrypted_page_is_corrupt() {
        use std::io::{Seek, SeekFrom, Write};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session.sqlite");
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "key", "test-only-key")
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('test payload');",
            )
            .unwrap();
        let root: i64 = connection
            .query_row(
                "SELECT rootpage FROM sqlite_master WHERE name='sample'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let page_size: i64 = connection
            .query_row("PRAGMA cipher_page_size", [], |r| r.get::<_, String>(0))
            .unwrap()
            .parse()
            .unwrap();
        connection.close().unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(
            ((root - 1) * page_size).try_into().unwrap(),
        ))
        .unwrap();
        file.write_all(&[0; 64]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "key", "test-only-key")
            .unwrap();
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Corrupt
        );
    }

    #[test]
    fn healthy_and_interrupted_checks_leave_connection_usable() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE sample(value INTEGER); WITH RECURSIVE values_to_check(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM values_to_check WHERE v<1000) INSERT INTO sample SELECT v FROM values_to_check;").unwrap();
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Healthy
        );
        assert_eq!(
            probe(&connection, Duration::ZERO),
            IntegrityProbe::Incomplete
        );
        assert_eq!(
            probe(&connection, Duration::from_nanos(1)),
            IntegrityProbe::Incomplete
        );
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Healthy
        );
    }

    #[test]
    fn corrupt_structure_is_reported_without_returning_private_diagnostics() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE sample(value TEXT CHECK(length(value) < 2)); PRAGMA ignore_check_constraints=ON; INSERT INTO sample VALUES ('private sentinel'); PRAGMA ignore_check_constraints=OFF;").unwrap();
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Corrupt
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM sample", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
