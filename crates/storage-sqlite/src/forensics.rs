//! Bounded local evidence, never SQL or row values. No database descriptors are
//! opened here: closing one would release this process's SQLite POSIX locks.
use rusqlite::Connection;
use serde::Serialize;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HISTORY: usize = 32;
const INTERVAL: Duration = Duration::from_secs(60);
static LIMITS: OnceLock<Mutex<Vec<(PathBuf, Instant)>>> = OnceLock::new();

#[derive(Serialize)]
struct ScopeTiming {
    elapsed_us: u128,
    sqlite_code: i32,
}

/// Captured once on an already-keyed connection. Missing values mean unavailable,
/// not healthy. No new diagnostic queries are run after a failure.
pub(crate) struct Recorder {
    path: Option<PathBuf>,
    page_size: Option<i64>,
    cipher_version: Option<String>,
    schema_version: Option<i64>,
    migration_version: Option<i64>,
    recent: Mutex<VecDeque<ScopeTiming>>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder").finish_non_exhaustive()
    }
}

impl Recorder {
    pub(crate) fn open_failure(connection: &Connection) {
        // Failed opening/key validation must not trigger further SQL queries.
        let recorder = Self {
            path: connection
                .path()
                .filter(|p| !p.is_empty())
                .map(PathBuf::from),
            page_size: None,
            cipher_version: None,
            schema_version: None,
            migration_version: None,
            recent: Mutex::new(VecDeque::new()),
        };
        recorder.finish(connection, Instant::now());
    }

    pub(crate) fn new(connection: &Connection) -> Self {
        Self {
            path: connection
                .path()
                .filter(|p| !p.is_empty())
                .map(PathBuf::from),
            page_size: connection
                .query_row("PRAGMA page_size", [], |r| match r.get_ref(0)? {
                    rusqlite::types::ValueRef::Integer(n) => Ok(n),
                    rusqlite::types::ValueRef::Text(bytes) => std::str::from_utf8(bytes)
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok())
                        .ok_or(rusqlite::Error::InvalidQuery),
                    _ => Err(rusqlite::Error::InvalidQuery),
                })
                .ok(),
            cipher_version: connection
                .query_row("PRAGMA cipher_version", [], |r| r.get::<_, String>(0))
                .ok()
                .filter(|s| s.len() <= 128),
            schema_version: connection
                .query_row("PRAGMA schema_version", [], |r| r.get(0))
                .ok(),
            migration_version: connection
                .query_row("SELECT max(version) FROM cgka_schema_migrations", [], |r| {
                    r.get(0)
                })
                .ok(),
            recent: Mutex::new(VecDeque::with_capacity(HISTORY)),
        }
    }

    pub(crate) fn finish(&self, connection: &Connection, started: Instant) {
        // SAFETY: the caller still holds the connection mutex; the handle is
        // live and no other thread can use/close it during this read-only call.
        let code = unsafe { rusqlite::ffi::sqlite3_extended_errcode(connection.handle()) };
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        if recent.len() == HISTORY {
            recent.pop_front();
        }
        recent.push_back(ScopeTiming {
            elapsed_us: started.elapsed().as_micros(),
            sqlite_code: code,
        });
        if matches!(
            code & 0xff,
            rusqlite::ffi::SQLITE_CORRUPT
                | rusqlite::ffi::SQLITE_NOTADB
                | rusqlite::ffi::SQLITE_IOERR
        ) {
            self.capture(code, &recent);
        }
    }

    /// Also usable by a structural probe whose bad result is a row, not a SQLite
    /// error. Integration with PR1937 calls this before dropping its guard.
    pub(crate) fn integrity_failure(&self) {
        let recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        self.capture(rusqlite::ffi::SQLITE_CORRUPT, &recent);
    }

    fn capture(&self, code: i32, recent: &VecDeque<ScopeTiming>) {
        let Some(path) = &self.path else { return };
        if !admit(path, Instant::now()) {
            return;
        }
        let report = serde_json::json!({
            "format_version": 1,
            "timestamp_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
            "pid": std::process::id(), "sqlite_extended_code": code,
            "classification": if code & 0xff == rusqlite::ffi::SQLITE_NOTADB { "unreadable_or_wrong_key" } else { "storage_failure" },
            "database_path": path, "database": file_metadata(path),
            "wal": file_metadata(&sidecar(path, "-wal")), "shm": file_metadata(&sidecar(path, "-shm")),
            "page_size_at_connection_wrap": self.page_size,
            "cipher_version_at_connection_wrap": self.cipher_version,
            "schema_version_at_connection_wrap": self.schema_version,
            "max_migration_at_connection_wrap": self.migration_version,
            "page_number": null,
            "page_number_unavailable_reason": "SQLite result codes do not expose SQLCipher failing page numbers",
            "recent_connection_scopes": recent,
            "history_scope": "connection guard lifetimes, not individual SQL statements",
            "open_descriptors": descriptor_owners(path),
            "disk_error_counters": null,
            "disk_error_counters_unavailable_reason": "no portable per-file kernel error counter",
        });
        let saved = persist(path, &report).is_ok();
        tracing::error!(target: "storage_sqlite::forensics", method = "capture", sqlite_code = code, evidence_saved = saved, "storage failure forensic capture attempted");
    }
}

fn admit(path: &Path, now: Instant) -> bool {
    let mut entries = LIMITS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    entries.retain(|(_, at)| now.duration_since(*at) < INTERVAL);
    if entries.iter().any(|(p, _)| p == path) || entries.len() >= 256 {
        return false;
    }
    entries.push((path.to_owned(), now));
    true
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn file_metadata(path: &Path) -> serde_json::Value {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            serde_json::json!({"bytes": m.len(), "regular_file": m.is_file(), "mtime_ms": m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_millis())})
        }
        Err(_) => serde_json::Value::Null,
    }
}

// A bounded best-effort Linux snapshot. Never open database or /proc/PID/fd/N
// targets; readlink does not acquire/release a descriptor on the DB inode.
fn descriptor_owners(path: &Path) -> serde_json::Value {
    let Ok(processes) = fs::read_dir("/proc") else {
        return serde_json::json!({"available": false});
    };
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let mut owners = Vec::new();
    let started = Instant::now();
    let mut scanned = 0;
    let mut inaccessible = 0;
    for process in processes.take(4096).flatten() {
        if started.elapsed() >= Duration::from_millis(50) {
            break;
        }
        let Ok(pid) = process.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(process.path().join("fd")) else {
            inaccessible += 1;
            continue;
        };
        for fd in fds.take(256).flatten() {
            if started.elapsed() >= Duration::from_millis(50) {
                break;
            }
            scanned += 1;
            if fs::read_link(fd.path()).ok().as_ref() == Some(&target) {
                owners
                    .push(serde_json::json!({"pid": pid, "fd": fd.file_name().to_string_lossy()}));
                if owners.len() == 64 {
                    break;
                }
            }
        }
        if owners.len() == 64 {
            break;
        }
    }
    serde_json::json!({"available": true, "complete": false, "limits": {"process_entries":4096,"fds_per_process":256,"matches":64}, "scanned_fds": scanned,"inaccessible_processes": inaccessible,"matches":owners})
}

fn persist(path: &Path, report: &serde_json::Value) -> std::io::Result<()> {
    let destination = sidecar(path, ".forensics.json");
    let temporary = sidecar(path, &format!(".forensics.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    fs_private::set_private_file_mode(&mut options);
    let mut file = options.open(&temporary)?;
    let result = (|| {
        serde_json::to_writer(&mut file, report)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CloseableConnection;

    #[test]
    fn encrypted_failure_emits_private_record_without_payload_and_rate_limits() {
        use std::io::{Seek, SeekFrom};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "key", "fixture-key").unwrap();
        conn.execute_batch("CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('PRIVATE_PAYLOAD_SENTINEL');").unwrap();
        let page: i64 = conn
            .query_row(
                "SELECT rootpage FROM sqlite_master WHERE name='sample'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let size: i64 = conn
            .query_row("PRAGMA page_size", [], |r| match r.get_ref(0)? {
                rusqlite::types::ValueRef::Integer(n) => Ok(n),
                rusqlite::types::ValueRef::Text(bytes) => std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .ok_or(rusqlite::Error::InvalidQuery),
                _ => Err(rusqlite::Error::InvalidQuery),
            })
            .unwrap();
        conn.close().unwrap();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(((page - 1) * size) as u64))
            .unwrap();
        file.write_all(&[0; 64]).unwrap();
        drop(file);
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "key", "fixture-key").unwrap();
        let conn = CloseableConnection::new(conn, "fixture");
        {
            let guard = conn.lock().unwrap();
            assert!(
                guard
                    .query_row("SELECT value FROM sample", [], |r| r.get::<_, String>(0))
                    .is_err()
            );
        }
        let record = sidecar(&path, ".forensics.json");
        let first = fs::read(&record).unwrap();
        let text = String::from_utf8(first.clone()).unwrap();
        assert!(!text.contains("PRIVATE_PAYLOAD_SENTINEL"));
        assert!(!text.contains("fixture-key"));
        assert!(!text.contains("SELECT value"));
        let parsed: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(parsed["format_version"], 1);
        assert_eq!(parsed["page_size_at_connection_wrap"], size);
        conn.lock().unwrap().record_integrity_failure();
        assert_eq!(fs::read(&record).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(record).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn healthy_operations_keep_bounded_history_without_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("healthy.sqlite");
        let conn = CloseableConnection::new(Connection::open(&path).unwrap(), "fixture");
        for _ in 0..64 {
            conn.lock().unwrap().execute_batch("SELECT 1").unwrap();
        }
        assert!(!sidecar(&path, ".forensics.json").exists());
        conn.lock().unwrap().record_integrity_failure();
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(sidecar(&path, ".forensics.json")).unwrap()).unwrap();
        assert_eq!(
            record["recent_connection_scopes"].as_array().unwrap().len(),
            HISTORY
        );
    }

    #[test]
    fn failed_key_validation_captures_unreadable_not_proven_corrupt() {
        use crate::{SqlCipherKey, SqliteAccountStorage};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong-key.sqlite");
        let key = SqlCipherKey::new("key-one").unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        storage.close().unwrap();
        assert!(
            SqliteAccountStorage::open_encrypted(&path, &SqlCipherKey::new("key-two").unwrap())
                .is_err()
        );
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(sidecar(&path, ".forensics.json")).unwrap()).unwrap();
        assert_eq!(record["classification"], "unreadable_or_wrong_key");
        assert!(record["page_size_at_connection_wrap"].is_null());
    }

    #[cfg(unix)]
    #[test]
    fn capture_preserves_sqlite_reserved_lock_against_another_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "key", "lock-test-key").unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE sample(value INTEGER); BEGIN IMMEDIATE; INSERT INTO sample VALUES (1);").unwrap();
        let conn = CloseableConnection::new(conn, "fixture");
        conn.lock().unwrap().record_integrity_failure();
        let status = std::process::Command::new("python3")
            .args(["-c", "import fcntl,sys; f=open(sys.argv[1],'r+b');\ntry: fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB,1,1073741825)\nexcept BlockingIOError: sys.exit(0)\nsys.exit(1)"])
            .arg(&path).status().unwrap();
        assert!(
            status.success(),
            "capture must not release SQLite's process-owned POSIX lock"
        );
        conn.lock().unwrap().execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn publication_refuses_existing_temporary_symlink() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("fixture.sqlite");
            let victim = dir.path().join("victim");
            fs::write(&victim, "unchanged").unwrap();
            std::os::unix::fs::symlink(
                &victim,
                sidecar(&path, &format!(".forensics.{}.tmp", std::process::id())),
            )
            .unwrap();
            assert!(persist(&path, &serde_json::json!({"test":true})).is_err());
            assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
        }
    }
}
