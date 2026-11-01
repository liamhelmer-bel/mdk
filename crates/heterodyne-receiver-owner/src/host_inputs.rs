//! Root-selected source and descriptor pins. Parsing these records is not native
//! consent; the only admitted native result comes from the owned child channel.
use crate::initializer_entry as input;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::FromRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
type Result<T> = std::result::Result<T, ()>;
pub(crate) const PARENT: &str = "/opt/heterodyne-receiver/bin/heterodyne-receiver-host-parent";
pub(crate) const BOOTSTRAP: &str = "/opt/heterodyne-receiver/bin/heterodyne-receiver-bootstrap";
pub(crate) const ADMISSION: &str = "/var/lib/heterodyne/receiver-owner/admission-profile.json";
const LAUNCH: &str = "/var/lib/heterodyne/receiver-owner/host-launch-profile.json";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParentProfile {
    pub(crate) schema: String,
    pub(crate) parent_path: String,
    pub(crate) parent_sha256: String,
    pub(crate) installation_index_sha256: String,
    pub(crate) installation_source_sha256: String,
    pub(crate) semantic_factory_source_sha256: String,
    pub(crate) packet_sha256: String,
    pub(crate) producer_profile_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    schema: String,
    bootstrap_sha256: String,
    admission_profile_sha256: String,
}
pub(crate) fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
pub(crate) fn inherited(n: i32) -> Result<File> {
    if unsafe { libc::fcntl(n, libc::F_GETFD) } < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(n) })
}
pub(crate) fn open(path: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())
}
pub(crate) fn binary(path: &Path, expected: &str) -> Result<File> {
    if !input::hash(expected, 64) {
        return Err(());
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let before = f.metadata().map_err(|_| ())?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o555
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > 256 * 1024 * 1024
    {
        return Err(());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    let mut total = 0;
    loop {
        let n = f.read(&mut buffer).map_err(|_| ())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > before.len() {
            return Err(());
        }
        digest.update(&buffer[..n]);
    }
    let after = f.metadata().map_err(|_| ())?;
    let facts = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if total != before.len()
        || hex::encode(digest.finalize()) != expected
        || facts(&before) != facts(&after)
    {
        return Err(());
    }
    Ok(f)
}
pub(crate) fn profiles() -> Result<(File, ParentProfile, File)> {
    let admission = open(ADMISSION)?;
    let raw = input::protected_bytes(&admission)?;
    let launch: Launch = serde_json::from_value(
        receiver_installation_verifier::installation::parse_canonical(&input::protected_bytes(
            &open(LAUNCH)?,
        )?)
        .map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let p: ParentProfile = serde_json::from_value(
        receiver_installation_verifier::installation::parse_canonical(&raw).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    if launch.schema != "heterodyne-deployment-host-launch.v1"
        || launch.admission_profile_sha256 != sha(&raw)
        || p.schema != "heterodyne-deployment-parent-profile.v1"
        || p.parent_path != PARENT
        || [
            &p.installation_index_sha256,
            &p.installation_source_sha256,
            &p.semantic_factory_source_sha256,
            &p.packet_sha256,
            &p.producer_profile_sha256,
        ]
        .iter()
        .any(|v| !input::hash(v, 64))
    {
        return Err(());
    }
    let own = binary(Path::new(PARENT), &p.parent_sha256)?;
    let actual = std::fs::metadata("/proc/self/exe").map_err(|_| ())?;
    let m = own.metadata().map_err(|_| ())?;
    if (actual.dev(), actual.ino()) != (m.dev(), m.ino()) {
        return Err(());
    }
    Ok((
        admission,
        p,
        binary(Path::new(BOOTSTRAP), &launch.bootstrap_sha256)?,
    ))
}
