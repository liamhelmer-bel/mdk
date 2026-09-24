//! Owner-leased, encrypted session snapshots. The operator's whole-home cron
//! remains separate; these files are included in it but created by the app.
use crate::{AppError, MarmotApp};
use cgka_traits::storage::StorageProvider;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use storage_sqlite::IntegrityProbe;

const SNAPSHOT_BUDGET: Duration = Duration::from_secs(30);
const KEEP_GENERATIONS: usize = 7;
const PREFIX: &str = "session-";
const SUFFIX: &str = ".sqlite";

impl MarmotApp {
    fn require_session_backup_lease(&self) -> Result<(), AppError> {
        if self
            .root_runtime_lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none()
        {
            return Err(AppError::BlockingTask(
                "session backup requires the exclusive Marmot root lease".into(),
            ));
        }
        Ok(())
    }

    /// The caller must own the root runtime lease. Never expose this as a
    /// standalone CLI action against an active home.
    pub(crate) fn backup_account_session(
        &self,
        label: &str,
        cancelled: &AtomicBool,
    ) -> Result<IntegrityProbe, AppError> {
        self.require_session_backup_lease()?;
        let storage = self.account_storage(label)?;
        let lease = self
            .root_runtime_lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if lease.is_none() {
            return Err(AppError::BlockingTask(
                "session backup requires the exclusive Marmot root lease".into(),
            ));
        }
        let source = self.account_storage_path(label);
        let lock = crate::sqlcipher::database_open_lock(&source);
        let key = self.session_sqlcipher_key_locked(label, &lock.lock())?;
        let directory = self.account_dir(label).join("session-backups");
        prepare_private_directory(&directory)?;
        let mut generations = scan_generations(&directory)?;
        let sequence = generations
            .last()
            .map(|(sequence, _)| sequence.checked_add(1))
            .unwrap_or(Some(1))
            .ok_or_else(|| AppError::BlockingTask("backup generation exhausted".into()))?;
        let stem = format!("{PREFIX}{sequence:020}");
        let partial = directory.join(format!("{stem}.partial"));
        let published = directory.join(format!("{stem}{SUFFIX}"));
        // A crashed attempt leaves only a partial. MLS state can advance
        // during startup, so retry a changed generation within one budget.
        let started = Instant::now();
        let mut verified_generation = None;
        let mut status = IntegrityProbe::Incomplete;
        for _ in 0..3 {
            cleanup_partial(&partial)?;
            let before = storage.mls_write_generation();
            let result = storage_sqlite::create_encrypted_backup(
                &source,
                &partial,
                &key,
                SNAPSHOT_BUDGET.saturating_sub(started.elapsed()),
                cancelled,
            );
            let after = storage.mls_write_generation();
            match result {
                Ok(IntegrityProbe::Healthy) if before.is_some() && before == after => {
                    verified_generation = before;
                    status = IntegrityProbe::Healthy;
                    break;
                }
                Ok(IntegrityProbe::Healthy) => continue,
                Ok(other) => {
                    status = other;
                    break;
                }
                Err(error) => {
                    let _ = cleanup_partial(&partial);
                    return Err(error.into());
                }
            }
        }
        if status != IntegrityProbe::Healthy {
            cleanup_partial(&partial)?;
            return Ok(status);
        }
        fs::File::open(&partial)?.sync_all()?;
        fs::rename(&partial, &published)?;
        sync_directory(&directory)?;
        generations.push((sequence, published.clone()));
        for (_, older) in generations
            .iter()
            .take(generations.len().saturating_sub(KEEP_GENERATIONS))
        {
            fs::remove_file(older)?;
        }
        sync_directory(&directory)?;
        self.session_backup_generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                label.to_owned(),
                (verified_generation.expect("checked generation"), published),
            );
        Ok(IntegrityProbe::Healthy)
    }

    /// Recheck every published file and classify it for operator inspection.
    /// Only `session_backup_candidates` can present a path for restore review.
    pub fn session_backup_inventory(
        &self,
        label: &str,
    ) -> Result<Vec<(PathBuf, IntegrityProbe)>, AppError> {
        self.require_session_backup_lease()?;
        let _storage = self.account_storage(label)?;
        let lease = self
            .root_runtime_lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if lease.is_none() {
            return Err(AppError::BlockingTask(
                "session backup inventory requires the exclusive Marmot root lease".into(),
            ));
        }
        let directory = self.account_dir(label).join("session-backups");
        if !directory.exists() {
            return Ok(Vec::new());
        }
        prepare_private_directory(&directory)?;
        let source = self.account_storage_path(label);
        let lock = crate::sqlcipher::database_open_lock(&source);
        let key = self.session_sqlcipher_key_locked(label, &lock.lock())?;
        scan_generations(&directory).map(|generations| {
            generations
                .into_iter()
                .rev()
                .map(|(_, path)| {
                    let status =
                        storage_sqlite::verify_encrypted_backup(&path, &key, SNAPSHOT_BUDGET);
                    (path, status)
                })
                .collect()
        })
    }

    /// The verified snapshot of the current MLS generation only. Old epochs
    /// remain in inventory for forensic review but cannot be restore candidates.
    pub fn session_backup_candidates(&self, label: &str) -> Result<Vec<PathBuf>, AppError> {
        self.require_session_backup_lease()?;
        let current = self.account_storage(label)?.mls_write_generation();
        let expected = self
            .session_backup_generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(label)
            .cloned();
        let Some((generation, expected_path)) = expected else {
            return Ok(Vec::new());
        };
        if current != Some(generation) {
            return Ok(Vec::new());
        }
        let candidates = self
            .session_backup_inventory(label)?
            .into_iter()
            .filter_map(|(path, status)| {
                (path == expected_path && status == IntegrityProbe::Healthy).then_some(path)
            })
            .collect();
        if self.account_storage(label)?.mls_write_generation() != Some(generation) {
            return Ok(Vec::new());
        }
        Ok(candidates)
    }
}

fn scan_generations(directory: &Path) -> Result<Vec<(u64, PathBuf)>, AppError> {
    let mut generations = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(number) = name
            .strip_prefix(PREFIX)
            .and_then(|rest| rest.strip_suffix(SUFFIX))
        else {
            continue;
        };
        if number.len() != 20 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file() {
            continue;
        }
        if let Ok(sequence) = number.parse::<u64>() {
            generations.push((sequence, entry.path()));
        }
    }
    generations.sort_unstable_by_key(|(sequence, _)| *sequence);
    Ok(generations)
}

fn cleanup_partial(path: &Path) -> Result<(), AppError> {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let file = PathBuf::from(name);
        if let Err(error) = fs::remove_file(file)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_private_directory(path: &Path) -> Result<(), AppError> {
    fs_private::prepare_directory_path(
        path,
        fs_private::PRIVATE_DIR_MODE,
        fs_private::ExistingDirectoryMode::Enforce,
    )?;
    Ok(())
}

#[cfg(not(unix))]
fn prepare_private_directory(path: &Path) -> Result<(), AppError> {
    fs::create_dir_all(path)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), AppError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MarmotAppConfig;
    use marmot_account::AccountHome;
    use std::time::Instant;
    use storage_sqlite::{SqlCipherHardening, open_hardened_sqlcipher};

    #[test]
    fn keeps_seven_encrypted_generations_and_rechecks_corruption() {
        let home = tempfile::tempdir().unwrap();
        let account_home = AccountHome::open(home.path());
        account_home.create_account("alice").unwrap();
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            home.path(),
            Vec::new(),
            account_home,
            MarmotAppConfig::default(),
        )
        .unwrap();
        for _ in 0..8 {
            assert_eq!(
                app.backup_account_session("alice", &AtomicBool::new(false))
                    .unwrap(),
                IntegrityProbe::Healthy
            );
        }
        let inventory = app.session_backup_inventory("alice").unwrap();
        assert_eq!(inventory.len(), 7);
        let candidates = app.session_backup_candidates("alice").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            fs::read_dir(candidates[0].parent().unwrap())
                .unwrap()
                .count(),
            7,
            "only standalone published snapshots remain"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let directory = candidates[0].parent().unwrap();
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&candidates[0]).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(candidates[0].ends_with("session-00000000000000000008.sqlite"));
        assert!(
            !candidates[0]
                .with_file_name("session-00000000000000000001.sqlite")
                .exists()
        );
        let mut bytes = fs::read(&candidates[0]).unwrap();
        bytes[..64].fill(0);
        fs::write(&candidates[0], bytes).unwrap();
        let inventory = app.session_backup_inventory("alice").unwrap();
        assert_eq!(inventory[0].1, IntegrityProbe::Corrupt);
        assert!(app.session_backup_candidates("alice").unwrap().is_empty());
    }

    #[test]
    fn committed_new_generation_withholds_old_restore_candidate() {
        let home = tempfile::tempdir().unwrap();
        let account_home = AccountHome::open(home.path());
        account_home.create_account("alice").unwrap();
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            home.path(),
            Vec::new(),
            account_home,
            MarmotAppConfig::default(),
        )
        .unwrap();
        let source = app.account_storage_path("alice");
        let lock = crate::sqlcipher::database_open_lock(&source);
        let key = app
            .session_sqlcipher_key_locked("alice", &lock.lock())
            .unwrap();
        assert_eq!(
            app.backup_account_session("alice", &AtomicBool::new(false))
                .unwrap(),
            IntegrityProbe::Healthy
        );
        assert_eq!(app.session_backup_candidates("alice").unwrap().len(), 1);
        let other = rusqlite::Connection::open(&source).unwrap();
        open_hardened_sqlcipher(&other, &key, SqlCipherHardening::cipher_only()).unwrap();
        other
            .execute_batch("CREATE TABLE changed_generation(value INTEGER)")
            .unwrap();
        assert!(app.session_backup_candidates("alice").unwrap().is_empty());
        assert_eq!(
            app.backup_account_session("alice", &AtomicBool::new(false))
                .unwrap(),
            IntegrityProbe::Healthy
        );
        assert_eq!(app.session_backup_candidates("alice").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn leased_worker_writes_first_backup_on_staged_home() {
        let home = tempfile::tempdir().unwrap();
        let account_home = AccountHome::open(home.path());
        account_home.create_account("alice").unwrap();
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            home.path(),
            Vec::new(),
            account_home,
            MarmotAppConfig::default(),
        )
        .unwrap();
        let runtime = app.runtime();
        runtime.accounts().reconcile().await.unwrap();
        let managed = runtime.accounts().managed_accounts().unwrap();
        assert_eq!(managed.len(), 1);
        assert!(managed[0].running, "staged account worker did not start");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if !app.session_backup_candidates("alice").unwrap().is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                let directory = app.account_dir("alice").join("session-backups");
                let files = fs::read_dir(directory)
                    .map(|entries| {
                        entries
                            .filter_map(|entry| entry.ok().map(|item| item.file_name()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                panic!("leased worker did not publish a backup; files={files:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        runtime.shutdown().await;
    }
}
