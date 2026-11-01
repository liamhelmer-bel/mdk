//! Finite expiry derived from the Product-owned validated operation and exact
//! enrolled profile descriptor. This parser does not replace Product validation
//! or qualify the missing installed producer/custody opener.
use super::{ReceiverHold, digest};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
pub(super) struct Profile {
    file: File,
    sha256: String,
    lifetime: u64,
}
impl Profile {
    pub(super) fn open(file: File, expected: &str) -> Result<Self, ReceiverHold> {
        let lifetime = crate::protected_expiry_policy::verify_descriptor(&file, expected)
            .map_err(|_| ReceiverHold::Configuration)?;
        Ok(Self {
            file,
            sha256: expected.into(),
            lifetime,
        })
    }
    pub(super) fn check(&self) -> Result<(), ReceiverHold> {
        if digest(&read(&self.file)?) != self.sha256 {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(())
    }
    pub(super) fn expiry(&self, canonical: &[u8], now_ms: u64) -> Result<u64, ReceiverHold> {
        self.check()?;
        let value: serde_json::Value =
            serde_json::from_slice(canonical).map_err(|_| ReceiverHold::Configuration)?;
        // Only this concrete Product packet family. Exact packet shape/recipes,
        // publication and card equivalence belong to the fixed owning producer.
        if value["schema"] != "heterodyne-protected-deployment.v1" {
            return Err(ReceiverHold::Configuration);
        }
        let bounds = |part: &str| -> Result<(u64, u64), ReceiverHold> {
            let before = value[part]["not_before_ns"]
                .as_u64()
                .ok_or(ReceiverHold::Configuration)?;
            let until = value[part]["deadline_ns"]
                .as_u64()
                .ok_or(ReceiverHold::Configuration)?;
            if before >= until {
                return Err(ReceiverHold::Configuration);
            }
            Ok((before, until))
        };
        let (release_start, release_end) = bounds("release")?;
        let (outage_start, outage_end) = bounds("outage")?;
        if release_start > outage_start || outage_end > release_end {
            return Err(ReceiverHold::Configuration);
        }
        let start_ms = outage_start.div_ceil(1_000_000);
        let deadline_ms = outage_end / 1_000_000;
        let policy_ms = now_ms
            .checked_add(self.lifetime)
            .ok_or(ReceiverHold::Configuration)?;
        let expiry = deadline_ms.min(policy_ms);
        if now_ms < start_ms || now_ms >= expiry {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(expiry)
    }
}
fn read(file: &File) -> Result<Vec<u8>, ReceiverHold> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let before = file.metadata().map_err(|_| ReceiverHold::Journal)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o7777 != 0o400
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || before.nlink() != 1
        || before.len() > 4096
    {
        return Err(ReceiverHold::Configuration);
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ReceiverHold::Journal)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| ReceiverHold::Journal)?;
    let after = file.metadata().map_err(|_| ReceiverHold::Journal)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() > 4096
    {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, os::unix::fs::PermissionsExt};

    #[test]
    fn policy_owner_must_be_actual_root_not_current_user() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owner-policy");
        let bytes = br#"{"schema":"heterodyne-receiver-expiry.v1","max_approval_lifetime_ms":100}"#;
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let result = Profile::open(File::open(path).unwrap(), &digest(bytes));
        if unsafe { libc::geteuid() } == 0 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(ReceiverHold::Configuration)));
        }
    }
    #[test]
    fn actual_expiry_descriptor_requires_root_readonly_exact_mode_and_retained_bytes() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("expiry");
        let bytes = br#"{"schema":"heterodyne-receiver-expiry.v1","max_approval_lifetime_ms":100}"#;
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let expected = digest(bytes);
        // This positive requires real UID 0 (qualified in a disposable user namespace).
        let profile = Profile::open(File::open(&path).unwrap(), &expected).unwrap();
        assert!(profile.check().is_ok());
        assert!(Profile::open(File::open(&path).unwrap(), &"55".repeat(32)).is_err());
        let writable = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            Profile::open(writable, &expected),
            Err(ReceiverHold::Configuration)
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(profile.check(), Err(ReceiverHold::Configuration)));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::hard_link(&path, root.path().join("alias")).unwrap();
        assert!(matches!(profile.check(), Err(ReceiverHold::Configuration)));
        std::fs::remove_file(root.path().join("alias")).unwrap();
        std::fs::write(&path, b"changed retained policy").unwrap();
        assert!(matches!(profile.check(), Err(ReceiverHold::ChangedState)));
    }
}
