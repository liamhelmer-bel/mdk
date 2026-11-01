//! Durable initialization phases. No receive runtime or network entry exists here.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_RECORD: usize = 65_536;
const MAX_RECORDS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("initialization ledger I/O; preserve generation and reconcile")]
    Io(#[from] std::io::Error),
    #[error("initialization ledger is partial, mismatched, or outside its closed contract")]
    Hold,
    #[error("initialization record encoding failed")]
    Encoding(#[from] serde_json::Error),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Intent,
    Material,
    Prepared,
    ExposureBegun,
    Published,
    ReceiverStarted,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) kind: u16,
    pub(crate) event_id: String,
    pub(crate) sha256: String,
    pub(crate) targets: Vec<String>,
    pub(crate) required_acks: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    schema: String,
    sequence: usize,
    previous_sha256: String,
    request_sha256: String,
    generation: String,
    phase: Phase,
    /// Stable OS-random slot, recorded before native lifecycle provisioning.
    slot: Option<String>,
    artifacts: Vec<Artifact>,
    accepted: Vec<Vec<String>>,
}

/// A retained descriptor, never a caller-supplied report or authority token.
pub(crate) struct Ledger {
    file: File,
    directory: File,
    last: Record,
    last_sha256: String,
    poisoned: bool,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn descriptor(file: &File, directory: &File) -> Result<(), Error> {
    let m = file.metadata()?;
    let d = directory.metadata()?;
    // SAFETY: both fcntl calls only inspect the retained descriptors.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let dir_flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: geteuid has no preconditions or side effects.
    let uid = unsafe { libc::geteuid() };
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != uid
        || m.mode() & 0o7777 != 0o600
        || !d.is_dir()
        || d.uid() != uid
        || d.mode() & 0o7777 != 0o700
        || m.dev() != d.dev()
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & (libc::O_APPEND | libc::O_PATH) != 0
        || dir_flags < 0
        || dir_flags & libc::O_PATH != 0
    {
        return Err(Error::Hold);
    }
    Ok(())
}

impl Ledger {
    pub(crate) fn create(
        mut file: File,
        directory: File,
        request: &str,
        generation: &str,
    ) -> Result<Self, Error> {
        descriptor(&file, &directory)?;
        if !hash(request) || !hash(generation) || file.metadata()?.len() != 0 {
            return Err(Error::Hold);
        }
        file.try_lock().map_err(|_| Error::Hold)?;
        let first = Record {
            schema: "heterodyne-receiver-initialization.v1".into(),
            sequence: 1,
            previous_sha256: "0".repeat(64),
            request_sha256: request.into(),
            generation: generation.into(),
            phase: Phase::Intent,
            slot: None,
            artifacts: vec![],
            accepted: vec![],
        };
        let bytes = serde_json::to_vec(&first)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        directory.sync_all()?;
        Ok(Self {
            file,
            directory,
            last: first,
            last_sha256: digest(&bytes),
            poisoned: false,
        })
    }

    pub(crate) fn reopen(
        mut file: File,
        directory: File,
        request: &str,
        generation: &str,
    ) -> Result<Self, Error> {
        descriptor(&file, &directory)?;
        file.try_lock().map_err(|_| Error::Hold)?;
        if file.metadata()?.len() > (MAX_RECORD * MAX_RECORDS) as u64 {
            return Err(Error::Hold);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![];
        Read::by_ref(&mut file)
            .take((MAX_RECORD * MAX_RECORDS + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty()
            || bytes.len() > MAX_RECORD * MAX_RECORDS
            || bytes.last() != Some(&b'\n')
        {
            return Err(Error::Hold);
        }
        let mut previous: Option<Record> = None;
        let mut previous_hash = "0".repeat(64);
        for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
            if line.len() > MAX_RECORD {
                return Err(Error::Hold);
            }
            let record: Record = serde_json::from_slice(line)?;
            if record.schema != "heterodyne-receiver-initialization.v1"
                || record.request_sha256 != request
                || record.generation != generation
                || !hash(request)
                || !hash(generation)
                || record.previous_sha256 != previous_hash
                || record.sequence != previous.as_ref().map_or(1, |r| r.sequence + 1)
                || record.sequence > MAX_RECORDS
            {
                return Err(Error::Hold);
            }
            if let Some(old) = previous.as_ref() {
                transition(old, &record)?;
            } else if record.phase != Phase::Intent
                || record.slot.is_some()
                || !record.artifacts.is_empty()
                || !record.accepted.is_empty()
            {
                return Err(Error::Hold);
            }
            previous_hash = digest(line);
            previous = Some(record);
        }
        Ok(Self {
            file,
            directory,
            last: previous.ok_or(Error::Hold)?,
            last_sha256: previous_hash,
            poisoned: false,
        })
    }

    fn append(&mut self, mut next: Record) -> Result<(), Error> {
        if self.poisoned || self.last.sequence >= MAX_RECORDS {
            return Err(Error::Hold);
        }
        next.sequence = self.last.sequence + 1;
        next.previous_sha256 = self.last_sha256.clone();
        transition(&self.last, &next)?;
        let bytes = serde_json::to_vec(&next)?;
        if bytes.len() > MAX_RECORD {
            return Err(Error::Hold);
        }
        self.poisoned = true;
        descriptor(&self.file, &self.directory)?;
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&bytes)?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.last_sha256 = digest(&bytes);
        self.last = next;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn material(&mut self, slot: String) -> Result<(), Error> {
        let mut next = self.last.clone();
        next.phase = Phase::Material;
        next.slot = Some(slot);
        self.append(next)
    }

    pub(crate) fn prepared(&mut self, artifacts: Vec<Artifact>) -> Result<(), Error> {
        let mut next = self.last.clone();
        next.phase = Phase::Prepared;
        next.artifacts = artifacts;
        next.accepted = next.artifacts.iter().map(|_| vec![]).collect();
        self.append(next)
    }

    /// Must complete before any of the exact retained artifacts is sent.
    pub(crate) fn exposure_begun(&mut self) -> Result<(), Error> {
        let mut next = self.last.clone();
        next.phase = Phase::ExposureBegun;
        self.append(next)
    }

    pub(crate) fn published(&mut self, accepted: Vec<Vec<String>>) -> Result<(), Error> {
        let mut next = self.last.clone();
        next.phase = Phase::Published;
        next.accepted = accepted;
        self.append(next)
    }

    pub(crate) fn receiver_started(&mut self) -> Result<(), Error> {
        let mut next = self.last.clone();
        next.phase = Phase::ReceiverStarted;
        self.append(next)
    }
}

fn transition(old: &Record, new: &Record) -> Result<(), Error> {
    if old.schema != new.schema
        || old.request_sha256 != new.request_sha256
        || old.generation != new.generation
    {
        return Err(Error::Hold);
    }
    let good = match (old.phase, new.phase) {
        (Phase::Intent, Phase::Material) => {
            new.slot.as_deref().is_some_and(hash)
                && new.artifacts.is_empty()
                && new.accepted.is_empty()
        }
        (Phase::Material, Phase::Prepared) => {
            new.slot == old.slot
                && artifacts(&new.artifacts)
                && new.accepted == vec![Vec::<String>::new(); 3]
        }
        (Phase::Prepared, Phase::ExposureBegun) => {
            new.slot == old.slot && new.artifacts == old.artifacts && new.accepted == old.accepted
        }
        (Phase::ExposureBegun, Phase::Published) => {
            new.slot == old.slot && new.artifacts == old.artifacts && acknowledgments(new)
        }
        (Phase::Published, Phase::ReceiverStarted) => {
            new.slot == old.slot && new.artifacts == old.artifacts && new.accepted == old.accepted
        }
        _ => false,
    };
    if good { Ok(()) } else { Err(Error::Hold) }
}

fn artifacts(values: &[Artifact]) -> bool {
    values.len() == 3
        && values.iter().map(|a| a.kind).eq([10_002, 10_050, 30_443])
        && values.iter().all(|a| {
            hash(&a.event_id)
                && hash(&a.sha256)
                && !a.targets.is_empty()
                && a.targets.len() <= 16
                && a.required_acks > 0
                && a.required_acks <= a.targets.len()
                && a.targets
                    .iter()
                    .enumerate()
                    .all(|(i, t)| !t.is_empty() && t.len() <= 2048 && !a.targets[..i].contains(t))
        })
}

fn acknowledgments(record: &Record) -> bool {
    record.accepted.len() == record.artifacts.len()
        && record
            .accepted
            .iter()
            .zip(&record.artifacts)
            .all(|(acks, a)| {
                acks.len() >= a.required_acks
                    && acks.len() <= a.targets.len()
                    && acks
                        .iter()
                        .enumerate()
                        .all(|(i, e)| a.targets.contains(e) && !acks[..i].contains(e))
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, File, File) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.path().join("initialization.jsonl"))
            .unwrap();
        let directory = File::open(temp.path()).unwrap();
        (temp, file, directory)
    }

    fn retained_artifacts() -> Vec<Artifact> {
        [10_002, 10_050, 30_443]
            .into_iter()
            .map(|kind| Artifact {
                kind,
                event_id: "12".repeat(32),
                sha256: "34".repeat(32),
                targets: vec!["wss://relay.invalid".into()],
                required_acks: 1,
            })
            .collect()
    }

    #[test]
    fn exact_exposure_survives_restart_and_cannot_reprepare_or_rearm_receiver() {
        let (temp, file, dir) = fixture();
        let request = "aa".repeat(32);
        let generation = "bb".repeat(32);
        let mut ledger = Ledger::create(file, dir, &request, &generation).unwrap();
        ledger.material("cc".repeat(32)).unwrap();
        ledger.prepared(retained_artifacts()).unwrap();
        assert!(
            ledger
                .published(vec![vec!["wss://relay.invalid".into()]; 3])
                .is_err()
        );
        ledger.exposure_begun().unwrap();
        drop(ledger);
        let reopen = || {
            Ledger::reopen(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(temp.path().join("initialization.jsonl"))
                    .unwrap(),
                File::open(temp.path()).unwrap(),
                &request,
                &generation,
            )
        };
        let mut ledger = reopen().unwrap();
        assert_eq!(ledger.last.phase, Phase::ExposureBegun);
        assert!(ledger.prepared(retained_artifacts()).is_err());
        assert!(
            ledger
                .published(vec![vec!["wss://wrong.invalid".into()]; 3])
                .is_err()
        );
        ledger
            .published(vec![vec!["wss://relay.invalid".into()]; 3])
            .unwrap();
        ledger.receiver_started().unwrap();
        assert!(ledger.receiver_started().is_err());
        drop(ledger);
        assert_eq!(reopen().unwrap().last.phase, Phase::ReceiverStarted);
    }

    #[test]
    fn partial_tail_wrong_request_second_opener_and_changed_artifacts_hold() {
        let (temp, file, dir) = fixture();
        let request = "aa".repeat(32);
        let generation = "bb".repeat(32);
        let mut ledger = Ledger::create(file, dir, &request, &generation).unwrap();
        let path = temp.path().join("initialization.jsonl");
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap()
        };
        assert!(
            Ledger::reopen(
                open(),
                File::open(temp.path()).unwrap(),
                &request,
                &generation
            )
            .is_err()
        );
        ledger.material("cc".repeat(32)).unwrap();
        ledger.prepared(retained_artifacts()).unwrap();
        let mut changed = ledger.last.clone();
        changed.phase = Phase::ExposureBegun;
        changed.artifacts[0].sha256 = "de".repeat(32);
        assert!(ledger.append(changed).is_err());
        drop(ledger);
        assert!(
            Ledger::reopen(
                open(),
                File::open(temp.path()).unwrap(),
                &"dd".repeat(32),
                &generation
            )
            .is_err()
        );
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"partial\":")
            .unwrap();
        assert!(
            Ledger::reopen(
                open(),
                File::open(temp.path()).unwrap(),
                &request,
                &generation
            )
            .is_err()
        );
        assert!(std::fs::read(&path).unwrap().ends_with(b"{\"partial\":"));
    }
}
