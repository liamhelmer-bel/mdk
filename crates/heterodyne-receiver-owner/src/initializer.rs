//! Durable initialization phases. No receive runtime or network entry exists here.

use std::fs::File;
#[cfg(test)]
use std::io::{BufRead, BufReader, Read};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// The closed maximum includes three 16-target vectors, their accepted
// unions, a complete current attempt, and worst-case JSON escaping (6x).
// Bound each frame, never the number of historical attempts.
const MAX_RECORD: usize = 2 * 1024 * 1024;

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
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Attempt {
    Begun {
        artifact: usize,
        sequence: usize,
    },
    Reported {
        artifact: usize,
        sequence: usize,
        accepted: Vec<String>,
        failed: Vec<String>,
    },
    Unknown {
        artifact: usize,
        sequence: usize,
        failed: Vec<String>,
    },
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
    attempt: Option<Attempt>,
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
    fn exposure(&self) -> Result<&Record, Error> {
        if self.poisoned || self.last.phase != Phase::ExposureBegun {
            return Err(Error::Hold);
        }
        descriptor(&self.file, &self.directory)?;
        Ok(&self.last)
    }

    pub(crate) fn publication_bindings(&self) -> Result<Vec<Artifact>, Error> {
        Ok(self.exposure()?.artifacts.clone())
    }
    pub(crate) fn create(
        mut file: File,
        directory: File,
        request: &str,
        generation: &str,
    ) -> Result<Self, Error> {
        descriptor(&file, &directory)?;
        file.try_lock().map_err(|_| Error::Hold)?;
        if !hash(request) || !hash(generation) || file.metadata()?.len() != 0 {
            return Err(Error::Hold);
        }
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
            attempt: None,
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

    #[cfg(test)]
    pub(crate) fn reopen(
        mut file: File,
        directory: File,
        request: &str,
        generation: &str,
    ) -> Result<Self, Error> {
        descriptor(&file, &directory)?;
        file.try_lock().map_err(|_| Error::Hold)?;
        file.seek(SeekFrom::Start(0))?;
        // History is unbounded; bound each frame without buffering the entire
        // lifetime journal. Never compact away an ambiguous network attempt.
        let mut reader = BufReader::new(&mut file);
        let mut previous: Option<Record> = None;
        let mut previous_hash = "0".repeat(64);
        loop {
            let mut line = Vec::new();
            let count = Read::by_ref(&mut reader)
                .take((MAX_RECORD + 2) as u64)
                .read_until(b'\n', &mut line)?;
            if count == 0 {
                break;
            }
            if count > MAX_RECORD + 1 || line.pop() != Some(b'\n') {
                return Err(Error::Hold);
            }
            let record: Record = serde_json::from_slice(&line)?;
            if record.schema != "heterodyne-receiver-initialization.v1"
                || record.request_sha256 != request
                || record.generation != generation
                || !hash(request)
                || !hash(generation)
                || record.previous_sha256 != previous_hash
                || Some(record.sequence)
                    != previous
                        .as_ref()
                        .map_or(Some(1), |r| r.sequence.checked_add(1))
            {
                return Err(Error::Hold);
            }
            if let Some(old) = previous.as_ref() {
                transition(old, &record)?;
            } else if record.phase != Phase::Intent
                || record.slot.is_some()
                || !record.artifacts.is_empty()
                || !record.accepted.is_empty()
                || record.attempt.is_some()
            {
                return Err(Error::Hold);
            }
            previous_hash = digest(&line);
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
        if self.poisoned {
            return Err(Error::Hold);
        }
        next.sequence = self.last.sequence.checked_add(1).ok_or(Error::Hold)?;
        next.previous_sha256 = self.last_sha256.clone();
        transition(&self.last, &next)?;
        let bytes = serde_json::to_vec(&next)?;
        if bytes.len() > MAX_RECORD {
            return Err(Error::Hold);
        }
        descriptor(&self.file, &self.directory)?;
        self.file.seek(SeekFrom::End(0))?;
        self.poisoned = true;
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
        self.advance(Phase::ExposureBegun)
    }

    /// The marker includes the immutable artifact binding before every attempt.
    /// An unresolved earlier attempt remains in history when an explicitly
    /// admitted owner retries the same bytes; no automatic retry loop exists.
    pub(crate) fn begin_attempt(
        &mut self,
        artifact: usize,
        binding: &Artifact,
    ) -> Result<usize, Error> {
        if self.last.artifacts.get(artifact) != Some(binding) {
            return Err(Error::Hold);
        }
        let sequence = self.last.sequence.checked_add(1).ok_or(Error::Hold)?;
        let mut next = self.last.clone();
        next.attempt = Some(Attempt::Begun { artifact, sequence });
        self.append(next)?;
        Ok(sequence)
    }

    pub(crate) fn report_attempt(
        &mut self,
        sequence: usize,
        accepted: Vec<String>,
        failed: Vec<String>,
    ) -> Result<(), Error> {
        let Some(Attempt::Begun {
            artifact,
            sequence: original,
        }) = self.last.attempt
        else {
            return Err(Error::Hold);
        };
        if sequence != original {
            return Err(Error::Hold);
        }
        let mut next = self.last.clone();
        for endpoint in &accepted {
            if !next.accepted[artifact].contains(endpoint) {
                next.accepted[artifact].push(endpoint.clone());
            }
        }
        next.attempt = Some(Attempt::Reported {
            artifact,
            sequence,
            accepted,
            failed,
        });
        self.append(next)
    }

    pub(crate) fn unknown_attempt(
        &mut self,
        sequence: usize,
        failed: Vec<String>,
    ) -> Result<(), Error> {
        let Some(Attempt::Begun {
            artifact,
            sequence: original,
        }) = self.last.attempt
        else {
            return Err(Error::Hold);
        };
        if sequence != original {
            return Err(Error::Hold);
        }
        let mut next = self.last.clone();
        next.attempt = Some(Attempt::Unknown {
            artifact,
            sequence,
            failed,
        });
        self.append(next)
    }

    pub(crate) fn publication_slot(&self) -> Result<String, Error> {
        self.exposure()?.slot.clone().ok_or(Error::Hold)
    }

    pub(crate) fn accepted(&self, artifact: usize) -> Result<Vec<String>, Error> {
        self.exposure()?
            .accepted
            .get(artifact)
            .cloned()
            .ok_or(Error::Hold)
    }

    pub(crate) fn published(&mut self) -> Result<(), Error> {
        self.advance(Phase::Published)
    }

    #[cfg(test)]
    pub(crate) fn receiver_started(&mut self) -> Result<(), Error> {
        self.advance(Phase::ReceiverStarted)
    }

    fn advance(&mut self, phase: Phase) -> Result<(), Error> {
        let mut next = self.last.clone();
        next.phase = phase;
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
                && new.attempt.is_none()
        }
        (Phase::Material, Phase::Prepared) => {
            new.slot == old.slot
                && artifacts(&new.artifacts)
                && new.accepted == vec![Vec::<String>::new(); 3]
                && new.attempt.is_none()
        }
        (Phase::Prepared, Phase::ExposureBegun) => {
            new.slot == old.slot
                && new.artifacts == old.artifacts
                && new.accepted == old.accepted
                && new.attempt.is_none()
        }
        (Phase::ExposureBegun, Phase::ExposureBegun) => {
            new.slot == old.slot && new.artifacts == old.artifacts && attempt_transition(old, new)
        }
        (Phase::ExposureBegun, Phase::Published) => {
            new.slot == old.slot
                && new.artifacts == old.artifacts
                && acknowledgments(new)
                && new.accepted == old.accepted
                && new.attempt == old.attempt
        }
        (Phase::Published, Phase::ReceiverStarted) => {
            new.slot == old.slot
                && new.artifacts == old.artifacts
                && new.accepted == old.accepted
                && new.attempt == old.attempt
        }
        _ => false,
    };
    if good { Ok(()) } else { Err(Error::Hold) }
}

fn attempt_transition(old: &Record, new: &Record) -> bool {
    match &new.attempt {
        Some(Attempt::Begun { artifact, sequence }) => {
            *artifact < old.artifacts.len()
                && *sequence == new.sequence
                && new.accepted == old.accepted
        }
        Some(Attempt::Unknown {
            artifact,
            sequence,
            failed,
        }) => {
            old.attempt
                == Some(Attempt::Begun {
                    artifact: *artifact,
                    sequence: *sequence,
                })
                && new.accepted == old.accepted
                && failed.iter().enumerate().all(|(i, v)| {
                    old.artifacts[*artifact].targets.contains(v) && !failed[..i].contains(v)
                })
        }
        Some(Attempt::Reported {
            artifact,
            sequence,
            accepted,
            failed,
        }) => {
            if old.attempt
                != Some(Attempt::Begun {
                    artifact: *artifact,
                    sequence: *sequence,
                })
            {
                return false;
            }
            let targets = &old.artifacts[*artifact].targets;
            let valid = |values: &[String]| {
                values
                    .iter()
                    .enumerate()
                    .all(|(i, v)| targets.contains(v) && !values[..i].contains(v))
            };
            if !valid(accepted) || !valid(failed) || failed.iter().any(|v| accepted.contains(v)) {
                return false;
            }
            let mut expected = old.accepted.clone();
            for endpoint in accepted {
                if !expected[*artifact].contains(endpoint) {
                    expected[*artifact].push(endpoint.clone());
                }
            }
            new.accepted == expected
        }
        None => false,
    }
}

/// Match SDK URL identity before any exposure: reject aliases and malformed URLs.
pub(crate) fn valid_targets(values: &[String]) -> bool {
    if values.is_empty() || values.len() > 16 {
        return false;
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        if value.len() > 2048 {
            return false;
        }
        let Ok(url) = nostr::RelayUrl::parse(value) else {
            return false;
        };
        if url.to_string() != *value || parsed.contains(&url) {
            return false;
        }
        parsed.push(url);
    }
    true
}

fn artifacts(values: &[Artifact]) -> bool {
    values.len() == 3
        && values.iter().map(|a| a.kind).eq([10_002, 10_050, 30_443])
        && values.iter().all(|a| {
            hash(&a.event_id)
                && hash(&a.sha256)
                && valid_targets(&a.targets)
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
    fn sdk_equivalent_targets_and_invalid_urls_are_rejected() {
        assert!(!valid_targets(&[
            "wss://relay.invalid".into(),
            "wss://relay.invalid/".into()
        ]));
        assert!(!valid_targets(&["not a relay".into()]));
        assert!(valid_targets(&["wss://relay.invalid".into()]));
    }

    #[test]
    fn durable_ack_union_allows_promotion_readback_after_unknown_or_begun_retry() {
        for unknown in [false, true] {
            let (_temp, file, dir) = fixture();
            let mut ledger = Ledger::create(file, dir, &"aa".repeat(32), &"bb".repeat(32)).unwrap();
            ledger.material("cc".repeat(32)).unwrap();
            let artifacts = retained_artifacts();
            ledger.prepared(artifacts.clone()).unwrap();
            ledger.exposure_begun().unwrap();
            for (i, a) in artifacts.iter().enumerate() {
                let sequence = ledger.begin_attempt(i, a).unwrap();
                ledger
                    .report_attempt(sequence, a.targets.clone(), vec![])
                    .unwrap();
            }
            let sequence = ledger.begin_attempt(2, &artifacts[2]).unwrap();
            if unknown {
                ledger.unknown_attempt(sequence, vec![]).unwrap();
            }
            ledger.published().unwrap();
            assert_eq!(ledger.last.phase, Phase::Published);
        }
    }

    #[test]
    fn maximum_closed_targets_and_escaped_reports_fit_every_record() {
        let (temp, file, dir) = fixture();
        let mut ledger = Ledger::create(file, dir, &"aa".repeat(32), &"bb".repeat(32)).unwrap();
        ledger.material("cc".repeat(32)).unwrap();
        let mut artifacts = retained_artifacts();
        // Exercise the maximum accepted URL length and target count.
        for artifact in &mut artifacts {
            artifact.targets = (0..16)
                .map(|i| format!("wss://relay{i:02}.invalid/{}", "a".repeat(2026)))
                .collect();
            artifact.required_acks = 16;
        }
        ledger.prepared(artifacts.clone()).unwrap();
        ledger.exposure_begun().unwrap();
        for (i, artifact) in artifacts.iter().enumerate() {
            let sequence = ledger.begin_attempt(i, artifact).unwrap();
            ledger
                .report_attempt(sequence, artifact.targets.clone(), vec![])
                .unwrap();
        }
        ledger.published().unwrap();
        drop(ledger);
        let reopened = Ledger::reopen(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(temp.path().join("initialization.jsonl"))
                .unwrap(),
            File::open(temp.path()).unwrap(),
            &"aa".repeat(32),
            &"bb".repeat(32),
        )
        .unwrap();
        assert_eq!(reopened.last.phase, Phase::Published);
    }

    #[test]
    fn exact_exposure_survives_restart_and_cannot_reprepare_or_rearm_receiver() {
        let (temp, file, dir) = fixture();
        let request = "aa".repeat(32);
        let generation = "bb".repeat(32);
        let mut ledger = Ledger::create(file, dir, &request, &generation).unwrap();
        ledger.material("cc".repeat(32)).unwrap();
        ledger.prepared(retained_artifacts()).unwrap();
        assert!(ledger.published().is_err());
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
        assert!(ledger.published().is_err());
        for (index, artifact) in retained_artifacts().iter().enumerate() {
            let sequence = ledger.begin_attempt(index, artifact).unwrap();
            assert!(
                ledger
                    .report_attempt(sequence + 1, artifact.targets.clone(), vec![])
                    .is_err()
            );
            ledger
                .report_attempt(sequence, artifact.targets.clone(), vec![])
                .unwrap();
        }
        ledger.published().unwrap();
        ledger.receiver_started().unwrap();
        assert!(ledger.receiver_started().is_err());
        drop(ledger);
        assert_eq!(reopen().unwrap().last.phase, Phase::ReceiverStarted);
    }

    #[test]
    fn partial_reports_unknown_and_unbounded_history_preserve_original_attempts() {
        let (temp, file, dir) = fixture();
        let request = "aa".repeat(32);
        let generation = "bb".repeat(32);
        let mut ledger = Ledger::create(file, dir, &request, &generation).unwrap();
        ledger.material("cc".repeat(32)).unwrap();
        let mut bindings = retained_artifacts();
        bindings[0].targets.push("wss://second.invalid".into());
        bindings[0].required_acks = 2;
        ledger.prepared(bindings.clone()).unwrap();
        ledger.exposure_begun().unwrap();
        let original = ledger.begin_attempt(0, &bindings[0]).unwrap();
        ledger
            .report_attempt(
                original,
                vec![bindings[0].targets[0].clone()],
                vec![bindings[0].targets[1].clone()],
            )
            .unwrap();
        assert!(ledger.published().is_err());
        let changed = Artifact {
            sha256: "ee".repeat(32),
            ..bindings[0].clone()
        };
        assert!(ledger.begin_attempt(0, &changed).is_err());
        for _ in 0..80 {
            let sequence = ledger.begin_attempt(0, &bindings[0]).unwrap();
            ledger.unknown_attempt(sequence, vec![]).unwrap();
        }
        // A crash after the marker but before any report also remains exposed.
        let unfinished = ledger.begin_attempt(0, &bindings[0]).unwrap();
        drop(ledger);
        let mut ledger = Ledger::reopen(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(temp.path().join("initialization.jsonl"))
                .unwrap(),
            File::open(temp.path()).unwrap(),
            &request,
            &generation,
        )
        .unwrap();
        assert_eq!(
            ledger.last.attempt,
            Some(Attempt::Begun {
                artifact: 0,
                sequence: unfinished
            })
        );
        assert_eq!(
            ledger.last.accepted[0],
            vec![bindings[0].targets[0].clone()]
        );
        assert!(ledger.published().is_err());
        assert!(ledger.report_attempt(original, vec![], vec![]).is_err());
        let retry = ledger.begin_attempt(0, &bindings[0]).unwrap();
        assert!(
            ledger
                .report_attempt(retry, vec!["wss://foreign.invalid".into()], vec![])
                .is_err()
        );
        ledger
            .report_attempt(retry, bindings[0].targets.clone(), vec![])
            .unwrap();
        for (index, binding) in bindings.iter().enumerate().skip(1) {
            let sequence = ledger.begin_attempt(index, binding).unwrap();
            ledger
                .report_attempt(sequence, binding.targets.clone(), vec![])
                .unwrap();
        }
        ledger.published().unwrap();
        let contents = std::fs::read_to_string(temp.path().join("initialization.jsonl")).unwrap();
        assert!(contents.lines().count() > 160);
        assert!(contents.contains("wss://second.invalid"));
        assert!(contents.contains("\"state\":\"unknown\""));
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
