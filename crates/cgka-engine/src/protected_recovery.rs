//! Dormant owned-descriptor recovery foundation, not a public authority factory.
//! Protected path opening, account enrollment and native/semantic projection are
//! separate integration prerequisites; supplied descriptors are never user DTOs.
use cgka_traits::reporting::event_id_is_valid as is_hash;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_LINE: usize = 4 * 1024 * 1024;
const DOMAIN: &[u8] = b"heterodyne.receiver-recovery.v1\0";

#[derive(Debug, PartialEq, Eq)]
enum Hold {
    Io,
    Lock,
    Encoding,
    Changed,
    Clock,
    Reused,
    Latched,
}
type Result<T> = std::result::Result<T, Hold>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    account: String,
    group: String,
    operators: Vec<String>,
    source_profile_sha256: String,
    storage_generation: String,
    initial_native_state_sha256: String,
    welcome_provenance_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct UseKey {
    header_sha256: String,
    card_complete_sequence: u64,
    ask_id: String,
    original_operation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum TransitionKind {
    Original,
    Wire,
    Outcome,
    Outbound,
    Published,
    Decision,
    Conflict,
    Expired,
    NativeUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Header {
        enrollment: Enrollment,
        generation: String,
    },
    Transition {
        transition: TransitionKind,
        payload_hex: String,
    },
    CardComplete {
        ask_id: String,
        original_operation_sha256: String,
    },
    Consumed {
        key: UseKey,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sequence: u64,
    previous_sha256: String,
    local_unix_ms: u64,
    body: Body,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    sequence: u64,
    journal_sha256: String,
    previous_anchor_sha256: String,
    use_key: Option<UseKey>,
    sha256: String,
}

/// All handles must come from the eventually enrolled protected opener. It must
/// create new journal/anchor with O_EXCL, nofollow and parent custody checks, and
/// independently own anchor backup/restore and authenticated consumer custody.
/// This private seam verifies descriptor properties and actual kernel locks;
/// distinct inodes alone do NOT qualify independent protection.
struct OwnedFiles {
    journal: File,
    journal_directory: File,
    storage_lease: File,
    anchor: File,
    anchor_directory: File,
}

struct Journal {
    files: OwnedFiles,
    sequence: u64,
    digest: String,
    anchor_digest: String,
    header_digest: String,
    last_time: u64,
    latched: bool,
}

fn hash(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| Hold::Encoding)?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Hold::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| Hold::Clock)
}
fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|_| Hold::Io)
}

fn checked_files(files: OwnedFiles) -> Result<OwnedFiles> {
    use std::os::unix::fs::MetadataExt;
    let mut identities = BTreeSet::new();
    for f in [&files.journal, &files.storage_lease, &files.anchor] {
        let m = io(f.metadata())?;
        if !m.is_file()
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
            || !identities.insert((m.dev(), m.ino()))
        {
            return Err(Hold::Changed);
        }
        f.try_lock().map_err(|_| Hold::Lock)?;
    }
    for f in [&files.journal_directory, &files.anchor_directory] {
        if !io(f.metadata())?.is_dir() {
            return Err(Hold::Changed);
        }
    }
    Ok(files)
}
fn append(file: &mut File, value: &impl Serialize) -> Result<()> {
    let mut line = serde_json::to_vec(value).map_err(|_| Hold::Encoding)?;
    if line.len() >= MAX_LINE {
        return Err(Hold::Encoding);
    }
    line.push(b'\n');
    io(file.seek(SeekFrom::End(0)))?;
    io(file.write_all(&line))?;
    io(file.sync_all())
}
fn next<T: for<'a> Deserialize<'a> + Serialize>(
    reader: &mut BufReader<&File>,
) -> Result<Option<T>> {
    let mut line = Vec::new();
    io(reader
        .take((MAX_LINE + 1) as u64)
        .read_until(b'\n', &mut line))?;
    if line.is_empty() {
        return Ok(None);
    }
    if line.len() > MAX_LINE || line.pop() != Some(b'\n') {
        return Err(Hold::Encoding);
    }
    let value: T = serde_json::from_slice(&line).map_err(|_| Hold::Encoding)?;
    if serde_json::to_vec(&value).map_err(|_| Hold::Encoding)? != line {
        return Err(Hold::Encoding);
    }
    Ok(Some(value))
}
fn record_digest(r: &Record) -> Result<String> {
    hash(&(r.sequence, &r.previous_sha256, r.local_unix_ms, &r.body))
}
fn anchor_digest(a: &Anchor) -> Result<String> {
    hash(&(
        a.sequence,
        &a.journal_sha256,
        &a.previous_anchor_sha256,
        &a.use_key,
    ))
}

impl Journal {
    fn enroll(files: OwnedFiles, mut enrollment: Enrollment) -> Result<Self> {
        enrollment.operators.sort();
        if enrollment.operators.is_empty()
            || enrollment.operators.len() > 64
            || enrollment.operators.windows(2).any(|p| p[0] == p[1])
            || ![
                &enrollment.account,
                &enrollment.group,
                &enrollment.source_profile_sha256,
                &enrollment.storage_generation,
                &enrollment.initial_native_state_sha256,
                &enrollment.welcome_provenance_sha256,
            ]
            .iter()
            .all(|s| is_hash(s))
            || !enrollment.operators.iter().all(|s| is_hash(s))
        {
            return Err(Hold::Changed);
        }
        let files = checked_files(files)?;
        if io(files.journal.metadata())?.len() != 0 || io(files.anchor.metadata())?.len() != 0 {
            return Err(Hold::Changed);
        }
        let mut generation = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut generation);
        let mut journal = Self {
            files,
            sequence: 0,
            digest: String::new(),
            anchor_digest: String::new(),
            header_digest: String::new(),
            last_time: 0,
            latched: false,
        };
        journal.write(Body::Header {
            enrollment,
            generation: hex::encode(generation),
        })?;
        journal.header_digest = journal.digest.clone();
        // No ingress/card effect can occur until both newly-created directory
        // entries and their contents are positively durable.
        io(journal.files.journal_directory.sync_all())?;
        io(journal.files.anchor_directory.sync_all())?;
        Ok(journal)
    }

    /// Strict clean checkpoint recovery. A suffix ahead of the anchor remains
    /// HOLD until an actual semantic/native completion validator is integrated.
    fn reopen(files: OwnedFiles, expected: &Enrollment) -> Result<Self> {
        let files = checked_files(files)?;
        io((&files.journal).seek(SeekFrom::Start(0)))?;
        io((&files.anchor).seek(SeekFrom::Start(0)))?;
        let mut reader = BufReader::new(&files.journal);
        let mut anchors = BufReader::new(&files.anchor);
        let mut sequence = 0;
        let mut digest = String::new();
        let mut previous_anchor = String::new();
        let mut header_digest = String::new();
        let mut last_time = 0;
        let mut expected = expected.clone();
        expected.operators.sort();
        while let Some(record) = next::<Record>(&mut reader)? {
            let anchor = next::<Anchor>(&mut anchors)?.ok_or(Hold::Changed)?;
            if record.sequence != sequence + 1
                || record.previous_sha256 != digest
                || record.local_unix_ms < last_time
                || record_digest(&record)? != record.sha256
                || anchor.sequence != record.sequence
                || anchor.journal_sha256 != record.sha256
                || anchor.previous_anchor_sha256 != previous_anchor
                || anchor_digest(&anchor)? != anchor.sha256
            {
                return Err(Hold::Changed);
            }
            if sequence == 0 {
                match &record.body {
                    Body::Header {
                        enrollment,
                        generation,
                    } if enrollment == &expected && is_hash(generation) => {}
                    _ => return Err(Hold::Changed),
                }
                header_digest = record.sha256.clone();
            } else if matches!(record.body, Body::Header { .. }) {
                return Err(Hold::Changed);
            }
            let use_key = match &record.body {
                Body::Consumed { key } => Some(key.clone()),
                _ => None,
            };
            if anchor.use_key != use_key {
                return Err(Hold::Changed);
            }
            sequence = record.sequence;
            digest = record.sha256;
            previous_anchor = anchor.sha256;
            last_time = record.local_unix_ms;
        }
        if sequence == 0 || next::<Anchor>(&mut anchors)?.is_some() || now()? < last_time {
            return Err(Hold::Changed);
        }
        drop(reader);
        drop(anchors);
        Ok(Self {
            files,
            sequence,
            digest,
            anchor_digest: previous_anchor,
            header_digest,
            last_time,
            latched: false,
        })
    }

    fn write(&mut self, body: Body) -> Result<()> {
        if self.latched {
            return Err(Hold::Latched);
        }
        let time = now()?;
        if time < self.last_time {
            return Err(Hold::Clock);
        }
        self.validate_body(&body)?;
        let mut record = Record {
            sequence: self.sequence.checked_add(1).ok_or(Hold::Changed)?,
            previous_sha256: self.digest.clone(),
            local_unix_ms: time,
            body,
            sha256: String::new(),
        };
        record.sha256 = record_digest(&record)?;
        let mut anchor = Anchor {
            sequence: record.sequence,
            journal_sha256: record.sha256.clone(),
            previous_anchor_sha256: self.anchor_digest.clone(),
            use_key: match &record.body {
                Body::Consumed { key } => Some(key.clone()),
                _ => None,
            },
            sha256: String::new(),
        };
        anchor.sha256 = anchor_digest(&anchor)?;
        self.latched = true;
        append(&mut self.files.journal, &record)?;
        append(&mut self.files.anchor, &anchor)?;
        self.sequence = record.sequence;
        self.digest = record.sha256;
        self.anchor_digest = anchor.sha256;
        self.last_time = time;
        self.latched = false;
        Ok(())
    }

    fn validate_body(&self, body: &Body) -> Result<()> {
        match body {
            Body::Header { .. } if self.sequence != 0 => Err(Hold::Changed),
            Body::Transition { payload_hex, .. }
                if payload_hex.len() > 2 * 1024 * 1024
                    || !payload_hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !payload_hex.len().is_multiple_of(2) =>
            {
                Err(Hold::Encoding)
            }
            Body::CardComplete {
                ask_id,
                original_operation_sha256,
            } if !valid_ask(ask_id) || !is_hash(original_operation_sha256) => Err(Hold::Changed),
            Body::CardComplete { ask_id, .. } => self.card_unused(ask_id),
            Body::Consumed { key } => self.validate_use(key),
            _ => Ok(()),
        }
    }

    fn card_unused(&self, id: &str) -> Result<()> {
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let mut records = BufReader::new(&self.files.journal);
        while let Some(record) = next::<Record>(&mut records)? {
            if matches!(record.body, Body::CardComplete { ask_id, .. } if ask_id == id) {
                return Err(Hold::Reused);
            }
        }
        Ok(())
    }

    fn validate_use(&self, key: &UseKey) -> Result<()> {
        if key.header_sha256 != self.header_digest || key.card_complete_sequence > self.sequence {
            return Err(Hold::Changed);
        }
        // The independently owned anchor itself is the one-use index, scanned
        // incrementally with bounded RAM. No caller-created replay boolean.
        io((&self.files.anchor).seek(SeekFrom::Start(0)))?;
        let mut anchors = BufReader::new(&self.files.anchor);
        while let Some(anchor) = next::<Anchor>(&mut anchors)? {
            if anchor.use_key.as_ref() == Some(key) {
                return Err(Hold::Reused);
            }
        }
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let mut records = BufReader::new(&self.files.journal);
        while let Some(record) = next::<Record>(&mut records)? {
            if record.sequence == key.card_complete_sequence {
                return match record.body {
                    Body::CardComplete {
                        ask_id,
                        original_operation_sha256,
                    } if ask_id == key.ask_id
                        && original_operation_sha256 == key.original_operation_sha256 =>
                    {
                        Ok(())
                    }
                    _ => Err(Hold::Changed),
                };
            }
        }
        Err(Hold::Changed)
    }
}
fn valid_ask(id: &str) -> bool {
    id.len() == 4
        && id
            .bytes()
            .all(|b| b"23456789abcdefghjkmnpqrstuvwxyz".contains(&b))
}

#[cfg(test)]
#[path = "protected_recovery_tests.rs"]
mod tests;
