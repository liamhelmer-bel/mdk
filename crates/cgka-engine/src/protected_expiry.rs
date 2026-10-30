//! Finite expiry derived from the Product-owned validated operation and exact
//! enrolled profile descriptor. This parser does not replace Product validation
//! or qualify the missing installed producer/custody opener.
use super::{ReceiverHold, digest};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    max_approval_lifetime_ms: u64,
}
pub(super) struct Profile {
    file: File,
    sha256: String,
    lifetime: u64,
}
impl Profile {
    pub(super) fn open(file: File, expected: &str) -> Result<Self, ReceiverHold> {
        let bytes = read(&file)?;
        let policy: Policy =
            serde_json::from_slice(&bytes).map_err(|_| ReceiverHold::Configuration)?;
        if policy.schema != "heterodyne-receiver-expiry.v1"
            || policy.max_approval_lifetime_ms == 0
            || digest(&bytes) != expected
        {
            return Err(ReceiverHold::Configuration);
        }
        Ok(Self {
            file,
            sha256: expected.into(),
            lifetime: policy.max_approval_lifetime_ms,
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
    use std::os::unix::fs::MetadataExt;
    let before = file.metadata().map_err(|_| ReceiverHold::Journal)?;
    if !before.is_file() || before.mode() & 0o277 != 0 || before.nlink() != 1 || before.len() > 4096
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
