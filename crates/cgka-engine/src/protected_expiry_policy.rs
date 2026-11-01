//! Shared read-only finite expiry codec; no consent or authority constructor.
use cgka_traits::EngineError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    max_approval_lifetime_ms: u64,
}
fn refused() -> EngineError {
    EngineError::Other("protected expiry policy refused".into())
}
/// Validate exact retained root-owned, read-only expiry bytes and finite lifetime.
/// Returned lifetime is policy data, not evidence of approval.
pub fn verify_descriptor(file: &File, expected: &str) -> Result<u64, EngineError> {
    let before = file.metadata().map_err(|_| refused())?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o400
        || before.len() > 4096
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(refused());
    }
    let mut view = file;
    view.seek(SeekFrom::Start(0)).map_err(|_| refused())?;
    let mut bytes = Vec::new();
    view.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    let after = file.metadata().map_err(|_| refused())?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) || bytes.len() > 4096
        || hex::encode(Sha256::digest(&bytes)) != expected
    {
        return Err(refused());
    }
    let p: Policy = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    if p.schema != "heterodyne-receiver-expiry.v1" || p.max_approval_lifetime_ms == 0 {
        return Err(refused());
    }
    Ok(p.max_approval_lifetime_ms)
}
