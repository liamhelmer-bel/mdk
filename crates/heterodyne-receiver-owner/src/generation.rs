//! Fresh material creation beneath an already admitted retained parent.
//! This module grants no admission and never adopts an existing generation.

use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("fresh material I/O; retain partial generation for reconciliation")]
    Io(#[from] std::io::Error),
    #[error("fresh material custody or identity mismatch")]
    Hold,
}

pub(crate) struct Generation {
    directory: File,
    key: File,
    seed: File,
    database: File,
    // Keeping this actual OFD alive is necessary but not a child-cessation proof.
    lease: File,
}

fn directory(file: &File) -> Result<(), Error> {
    let m = file.metadata()?;
    // SAFETY: metadata-only calls on a live descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !m.is_dir()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o700
        || flags < 0
        || flags & libc::O_PATH != 0
    {
        return Err(Error::Hold);
    }
    Ok(())
}

fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File, Error> {
    let name = CString::new(name).map_err(|_| Error::Hold)?;
    // SAFETY: name is NUL terminated and parent is retained for this call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful openat returns a new uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn secret(parent: &File, name: &str, bytes: &[u8; 32]) -> Result<File, Error> {
    let mut file = open_at(
        parent,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o400,
    )?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let read = open_at(parent, name, libc::O_RDONLY, 0)?;
    if file.metadata()?.ino() != read.metadata()?.ino()
        || file.metadata()?.dev() != read.metadata()?.dev()
    {
        return Err(Error::Hold);
    }
    parent.sync_all()?;
    Ok(read)
}

impl Generation {
    /// The caller must durably record the request/generation/slot intent first.
    /// Any error leaves every already-created object intact; never call this as
    /// a retry of a partially created generation.
    pub(crate) fn create(parent: &File, generation: &str) -> Result<Self, Error> {
        directory(parent)?;
        if generation.len() != 64
            || !generation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Hold);
        }
        let name = CString::new(generation).map_err(|_| Error::Hold)?;
        // SAFETY: one fixed validated path component below a retained parent.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        parent.sync_all()?;
        let dir = open_at(parent, generation, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        directory(&dir)?;
        if dir.metadata()?.dev() != parent.metadata()?.dev() {
            return Err(Error::Hold);
        }
        let lease = open_at(
            &dir,
            "storage.lease",
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        lease.try_lock().map_err(|_| Error::Hold)?;
        lease.sync_all()?;
        let mut private = Zeroizing::new([0u8; 32]);
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(private.as_mut()).map_err(|_| Error::Hold)?;
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Hold)?;
        // No invalid scalar can become retained public identity or be silently
        // replaced after any file was written.
        nostr::SecretKey::from_slice(private.as_ref()).map_err(|_| Error::Hold)?;
        let key_file = secret(&dir, "nostr.key", &private)?;
        let seed_file = secret(&dir, "sqlcipher.seed", &seed)?;
        let database = open_at(
            &dir,
            "account.sqlite3",
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        database.sync_all()?;
        dir.sync_all()?;
        Ok(Self {
            directory: dir,
            key: key_file,
            seed: seed_file,
            database,
            lease,
        })
    }

    pub(crate) fn native_inputs(
        &self,
    ) -> Result<(PathBuf, nostr::Keys, storage_sqlite::SqlCipherKey), Error> {
        directory(&self.directory)?;
        let mut key = Zeroizing::new([0u8; 32]);
        let mut seed = Zeroizing::new([0u8; 32]);
        for (file, target) in [(&self.key, &mut key), (&self.seed, &mut seed)] {
            let m = file.metadata()?;
            if !m.is_file()
                || m.uid() != unsafe { libc::geteuid() }
                || m.nlink() != 1
                || m.mode() & 0o7777 != 0o400
                || m.len() != 32
            {
                return Err(Error::Hold);
            }
            // Pread avoids changing inherited OFD offsets on repeated readback.
            std::os::unix::fs::FileExt::read_exact_at(file, target.as_mut(), 0)?;
        }
        let database = open_at(&self.directory, "account.sqlite3", libc::O_RDONLY, 0)?;
        let a = database.metadata()?;
        let b = self.database.metadata()?;
        if !a.is_file()
            || a.nlink() != 1
            || a.uid() != unsafe { libc::geteuid() }
            || a.mode() & 0o7777 != 0o600
            || (a.dev(), a.ino()) != (b.dev(), b.ino())
        {
            return Err(Error::Hold);
        }
        let keys =
            nostr::Keys::new(nostr::SecretKey::from_slice(key.as_ref()).map_err(|_| Error::Hold)?);
        let encoded = Zeroizing::new(hex::encode(seed.as_ref()));
        let sql = storage_sqlite::SqlCipherKey::new(encoded.as_str()).map_err(|_| Error::Hold)?;
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/account.sqlite3",
            self.directory.as_raw_fd()
        ));
        Ok((path, keys, sql))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[tokio::test]
    async fn actual_material_native_preparation_and_no_existing_generation_adoption() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(root.path()).unwrap();
        let generation = "ab".repeat(32);
        let ledger_file = open_at(
            &parent,
            "initialization.jsonl",
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
        .unwrap();
        let mut ledger = crate::initializer::Ledger::create(
            ledger_file,
            parent.try_clone().unwrap(),
            &"12".repeat(32),
            &generation,
        )
        .unwrap();
        let slot = "cd".repeat(32);
        ledger.material(slot.clone()).unwrap();
        let material = Generation::create(&parent, &generation).unwrap();
        let (path, keys, sql) = material.native_inputs().unwrap();
        let public = keys.public_key();
        let prepared = crate::preparation::prepare(
            &path,
            &sql,
            keys.clone(),
            &slot,
            vec![cgka_traits::TransportEndpoint::from("wss://relay.invalid")],
        )
        .await
        .unwrap();
        assert_eq!(prepared.metadata.credential_identity_hex, public.to_hex());
        let relays = crate::preparation::relay_lists(
            &keys,
            prepared.artifact.created_at,
            vec![cgka_traits::TransportEndpoint::from(
                "wss://discovery.invalid",
            )],
            vec![cgka_traits::TransportEndpoint::from("wss://relay.invalid")],
        )
        .unwrap();
        let mut artifact_bindings = Vec::new();
        for (artifact, kind) in [&relays[0], &relays[1], &prepared.artifact]
            .into_iter()
            .zip([10002, 10050, 30443])
        {
            use nostr::JsonUtil;
            use sha2::Digest;
            let event: transport_nostr_peeler::NostrTransportEvent =
                serde_json::from_slice(&artifact.bytes).unwrap();
            assert_eq!(event.kind, kind);
            let signed = nostr::Event::from_json(serde_json::to_string(&event).unwrap()).unwrap();
            signed.verify().unwrap();
            assert_eq!(signed.pubkey, public);
            artifact_bindings.push(crate::initializer::Artifact {
                kind: kind as u16,
                event_id: hex::encode(artifact.id.as_slice()),
                sha256: hex::encode(sha2::Sha256::digest(&artifact.bytes)),
                targets: vec!["wss://discovery.invalid".into()],
                required_acks: 1,
            });
        }
        ledger.prepared(artifact_bindings).unwrap();
        ledger.exposure_begun().unwrap();
        drop(ledger);
        let ledger_file = open_at(&parent, "initialization.jsonl", libc::O_RDWR, 0).unwrap();
        let mut ledger = crate::initializer::Ledger::reopen(
            ledger_file,
            parent.try_clone().unwrap(),
            &"12".repeat(32),
            &generation,
        )
        .unwrap();
        assert!(ledger.material(slot).is_err());
        assert!(Generation::create(&parent, &generation).is_err());
        let (same_path, same_keys, same_sql) = material.native_inputs().unwrap();
        assert_eq!(same_path, path);
        assert_eq!(same_keys.public_key(), public);
        assert_eq!(same_sql.as_secret_str(), sql.as_secret_str());
        let second = open_at(&material.directory, "storage.lease", libc::O_RDWR, 0).unwrap();
        assert!(second.try_lock().is_err());
        assert!(material.lease.metadata().unwrap().is_file());
        assert_eq!(material.key.metadata().unwrap().len(), 32);
    }

    #[test]
    fn symlink_generation_and_database_replacement_refuse_without_cleanup() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(root.path()).unwrap();
        let generation = "ab".repeat(32);
        symlink(root.path(), root.path().join(&generation)).unwrap();
        assert!(Generation::create(&parent, &generation).is_err());
        assert!(root.path().join(&generation).is_symlink());
        let generation = "cd".repeat(32);
        let material = Generation::create(&parent, &generation).unwrap();
        let path = root.path().join(&generation).join("account.sqlite3");
        std::fs::rename(&path, path.with_extension("retained")).unwrap();
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(material.native_inputs().is_err());
        assert!(path.with_extension("retained").exists());
    }
}
