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

const MAX_LINE: usize = 12 * 1024 * 1024;
const DOMAIN: &[u8] = b"heterodyne.receiver-recovery.v1\0";

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Hold {
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
struct LegacyEnrollment {
    pub(super) account: String,
    pub(super) group: String,
    pub(super) operators: Vec<String>,
    pub(super) source_profile_sha256: String,
    pub(super) storage_generation: String,
    pub(super) initial_native_state_sha256: String,
    pub(super) welcome_provenance_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Enrollment {
    pub(super) schema: String,
    pub(super) account: String,
    pub(super) group: String,
    pub(super) operators: Vec<String>,
    pub(super) source_profile_sha256: String,
    pub(super) storage_generation: String,
    pub(super) initial_native_state_sha256: String,
    pub(super) welcome_provenance_sha256: String,
    pub(super) expiry_profile_sha256: String,
}

impl Enrollment {
    pub(super) const SCHEMA: &str = "heterodyne-receiver-enrollment.v2";
    pub(super) fn check(&self) -> Result<()> {
        if self.schema != Self::SCHEMA
            || self.operators.is_empty()
            || self.operators.len() > 64
            || self.operators.windows(2).any(|p| p[0] >= p[1])
            || ![
                &self.account,
                &self.source_profile_sha256,
                &self.storage_generation,
                &self.initial_native_state_sha256,
                &self.welcome_provenance_sha256,
                &self.expiry_profile_sha256,
            ]
            .iter()
            .all(|v| is_hash(v))
            || !valid_group(&self.group)
            || !self.operators.iter().all(|v| is_hash(v))
        {
            return Err(Hold::Changed);
        }
        Ok(())
    }
    pub(super) fn canonical_sha256(&self) -> Result<String> {
        self.check()?;
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| Hold::Encoding)?,
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct UseKey {
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
    Enrollment,
    Consumed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Body {
    Header {
        enrollment: LegacyEnrollment,
        generation: String,
    },
    HeaderV2 {
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
pub(super) struct OwnedFiles {
    pub(super) journal: File,
    pub(super) journal_directory: File,
    pub(super) storage_lease: File,
    pub(super) anchor: File,
    pub(super) anchor_directory: File,
}

pub(super) struct Journal {
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
    reader: &mut BufReader<impl Read>,
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

/// Non-authoritative readback from this exclusively owned, anchored journal.
/// Original source bytes remain on disk; each allocation is bounded by MAX_LINE.
pub(super) struct SourceRecord {
    pub(super) sequence: u64,
    pub(super) local_unix_ms: u64,
    pub(super) body: serde_json::Value,
}
struct Positioned {
    file: File,
    offset: u64,
}
impl Read for Positioned {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let length = self.file.read_at(buffer, self.offset)?;
        self.offset = self
            .offset
            .checked_add(length as u64)
            .ok_or_else(|| std::io::Error::other("journal offset"))?;
        Ok(length)
    }
}
pub(super) struct SourceCursor {
    reader: BufReader<Positioned>,
    sequence: u64,
    digest: String,
    tail: (u64, String),
}
impl SourceCursor {
    pub(super) fn offset(&self) -> u64 {
        self.reader.get_ref().offset - self.reader.buffer().len() as u64
    }
    pub(super) fn next(&mut self) -> Result<Option<SourceRecord>> {
        let Some(record) = next::<Record>(&mut self.reader)? else {
            if (self.sequence, self.digest.clone()) != self.tail {
                return Err(Hold::Changed);
            }
            return Ok(None);
        };
        if record.sequence != self.sequence.checked_add(1).ok_or(Hold::Changed)?
            || record.previous_sha256 != self.digest
            || record_digest(&record)? != record.sha256
            || record.sequence > self.tail.0
        {
            return Err(Hold::Changed);
        }
        match &record.body {
            Body::Header { .. } => return Err(Hold::Changed),
            Body::HeaderV2 { enrollment, .. } if record.sequence == 1 => enrollment.check()?,
            Body::HeaderV2 { .. } => return Err(Hold::Changed),
            _ if record.sequence == 1 => return Err(Hold::Changed),
            _ => (),
        }
        self.sequence = record.sequence;
        self.digest = record.sha256;
        let body = match record.body {
            Body::Transition { payload_hex, .. } => serde_json::json!({"kind":"source", "value":
                serde_json::from_slice::<serde_json::Value>(&hex::decode(payload_hex).map_err(|_|Hold::Encoding)?).map_err(|_|Hold::Encoding)?}),
            other => serde_json::to_value(other).map_err(|_| Hold::Encoding)?,
        };
        Ok(Some(SourceRecord {
            sequence: record.sequence,
            local_unix_ms: record.local_unix_ms,
            body,
        }))
    }
}

impl Journal {
    /// Preflight and retain exact fresh descriptor locks before any native join.
    /// This verifies mechanics, not protected publisher or independent custody.
    pub(super) fn prepare_fresh(files: OwnedFiles) -> Result<OwnedFiles> {
        let files = checked_files(files)?;
        if io(files.journal.metadata())?.len() != 0 || io(files.anchor.metadata())?.len() != 0 {
            return Err(Hold::Changed);
        }
        io(files.journal_directory.sync_all())?;
        io(files.anchor_directory.sync_all())?;
        Ok(files)
    }

    pub(super) fn enroll(files: OwnedFiles, enrollment: Enrollment) -> Result<Self> {
        enrollment.check()?;
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
        journal.write(Body::HeaderV2 {
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
    pub(super) fn reopen(files: OwnedFiles, expected: &Enrollment) -> Result<Self> {
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
        expected.check()?;
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
                    Body::HeaderV2 {
                        enrollment,
                        generation,
                    } if enrollment == expected && is_hash(generation) => {}
                    _ => return Err(Hold::Changed),
                }
                header_digest = record.sha256.clone();
            } else if matches!(record.body, Body::HeaderV2 { .. } | Body::Header { .. }) {
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

    /// Stream original protected source records, retaining only the actual
    /// pending projection set. No lifetime history materialization or replay.
    pub(super) fn verify_pending(
        &self,
        pending: &[crate::protected_receiver::PendingApplicationProjection],
    ) -> Result<()> {
        use crate::protected_receiver::{RetainedOutcome, RetainedWire};
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let mut reader = BufReader::new(&self.files.journal);
        let mut wire: Option<RetainedWire> = None;
        let mut sequence = 0u64;
        let mut matches = vec![0u8; pending.len()];
        while let Some(record) = next::<Record>(&mut reader)? {
            let Body::Transition {
                transition,
                payload_hex,
            } = record.body
            else {
                continue;
            };
            let bytes = hex::decode(payload_hex).map_err(|_| Hold::Encoding)?;
            match transition {
                TransitionKind::Wire => {
                    let retained: RetainedWire =
                        serde_json::from_slice(&bytes).map_err(|_| Hold::Encoding)?;
                    if retained.schema != "receiver-wire.v1"
                        || wire.is_some()
                        || retained.sequence != sequence.checked_add(1).ok_or(Hold::Changed)?
                    {
                        return Err(Hold::Changed);
                    }
                    wire = Some(retained);
                }
                TransitionKind::Outcome => {
                    let outcome: RetainedOutcome =
                        serde_json::from_slice(&bytes).map_err(|_| Hold::Encoding)?;
                    let original = wire.take().ok_or(Hold::Changed)?;
                    if outcome.schema != "receiver-outcome.v1"
                        || outcome.sequence != original.sequence
                        || outcome.message_id != hex::encode(original.wire.id.as_slice())
                        || outcome.pending_application_ids.len()
                            != outcome.pending_application_projections.len()
                        || !matches!(
                            outcome.outcome,
                            cgka_traits::ingest::IngestOutcome::Processed
                                | cgka_traits::ingest::IngestOutcome::Ignored { .. }
                                | cgka_traits::ingest::IngestOutcome::Rejected { .. }
                        )
                    {
                        return Err(Hold::Changed);
                    }
                    // Readback DTOs cannot mint native evidence. This method
                    // verifies only pending plaintext projection/acknowledgment;
                    // native update reconstruction remains a separate validator.
                    if outcome.candidate.as_ref().is_some_and(|candidate| {
                        !candidate
                            .matches_retained(&original, &outcome.pending_application_projections)
                    }) || (outcome.native_merge.is_some()
                        && !outcome.pending_application_projections.is_empty())
                    {
                        return Err(Hold::Changed);
                    }
                    for (id, projection) in outcome
                        .pending_application_ids
                        .iter()
                        .zip(&outcome.pending_application_projections)
                    {
                        if !projection.matches_id(id) {
                            return Err(Hold::Changed);
                        }
                        for (index, actual) in pending.iter().enumerate() {
                            if actual == projection {
                                matches[index] =
                                    matches[index].checked_add(1).ok_or(Hold::Changed)?;
                            }
                        }
                    }
                    sequence = outcome.sequence;
                }
                _ => {}
            }
        }
        if wire.is_some() || matches.iter().any(|count| *count != 1) {
            return Err(Hold::Changed);
        }
        Ok(())
    }

    /// Fixed fresh native enrollment; the original authenticated Welcome remains
    /// retained in this chain before native pending plaintext can be acknowledged.
    pub(super) fn retain_join(
        &mut self,
        evidence: &crate::protected_join::JoinEvidence,
    ) -> Result<()> {
        if self.sequence != 1 || self.latched {
            return Err(Hold::Changed);
        }
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let header =
            next::<Record>(&mut BufReader::new(&self.files.journal))?.ok_or(Hold::Changed)?;
        let Body::HeaderV2 { enrollment, .. } = header.body else {
            return Err(Hold::Changed);
        };
        if enrollment.welcome_provenance_sha256 != evidence.digest().map_err(|_| Hold::Changed)? {
            return Err(Hold::Changed);
        }
        self.record_source(
            serde_json::json!({"schema":"receiver-enrollment.v1", "native_join":evidence}),
        )
    }

    pub(super) fn source_cursor(&self) -> Result<SourceCursor> {
        if self.latched {
            return Err(Hold::Latched);
        }
        Ok(SourceCursor {
            reader: BufReader::new(Positioned {
                file: io(self.files.journal.try_clone())?,
                offset: 0,
            }),
            sequence: 0,
            digest: String::new(),
            tail: self.checkpoint(),
        })
    }
    /// Continuation selected only by the owned derived catalog's prior verified
    /// cursor. These scalar values cannot themselves establish journal authority.
    pub(super) fn source_after(
        &self,
        sequence: u64,
        digest: String,
        offset: u64,
    ) -> Result<SourceCursor> {
        if self.latched || sequence > self.sequence || offset > self.length()? {
            return Err(Hold::Changed);
        }
        Ok(SourceCursor {
            reader: BufReader::new(Positioned {
                file: io(self.files.journal.try_clone())?,
                offset,
            }),
            sequence,
            digest,
            tail: self.checkpoint(),
        })
    }
    pub(super) fn enrollment(&self) -> Result<Enrollment> {
        let record = self.source_at(1)?;
        if record.sequence != 1 || record.body["kind"] != "header-v2" {
            return Err(Hold::Changed);
        }
        let enrollment: Enrollment = serde_json::from_value(record.body["enrollment"].clone())
            .map_err(|_| Hold::Encoding)?;
        enrollment.check()?;
        Ok(enrollment)
    }
    pub(super) fn header_hash(&self) -> &str {
        &self.header_digest
    }
    pub(super) fn header_digest(&self) -> Result<String> {
        if self.latched {
            return Err(Hold::Latched);
        }
        Ok(self.header_digest.clone())
    }

    pub(super) fn checkpoint(&self) -> (u64, String) {
        (self.sequence, self.digest.clone())
    }
    pub(super) fn source_at(&self, sequence: u64) -> Result<SourceRecord> {
        let mut cursor = self.source_cursor()?;
        while let Some(record) = cursor.next()? {
            if record.sequence == sequence {
                return Ok(record);
            }
        }
        Err(Hold::Changed)
    }

    pub(super) fn checked_now(&self) -> Result<u64> {
        if self.latched {
            return Err(Hold::Latched);
        }
        let time = now()?;
        if time < self.last_time {
            return Err(Hold::Clock);
        }
        Ok(time)
    }
    pub(super) fn fresh_source_profile_hash(&self) -> Result<String> {
        Ok(self.enrollment()?.source_profile_sha256)
    }

    pub(super) fn expiry_profile_hash(&self) -> Result<String> {
        Ok(self.enrollment()?.expiry_profile_sha256)
    }

    pub(super) fn length(&self) -> Result<u64> {
        Ok(io(self.files.journal.metadata())?.len())
    }

    pub(super) fn binds_native(
        &self,
        account: &str,
        group: &str,
        operators: &[String],
        native: &str,
    ) -> Result<bool> {
        // This bridge is fresh-only; a historical journal requires the separate
        // complete semantic/native restart validator, never a reset sequence.
        if self.sequence != 1 || self.latched {
            return Ok(false);
        }
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let record =
            next::<Record>(&mut BufReader::new(&self.files.journal))?.ok_or(Hold::Changed)?;
        let mut operators = operators.to_vec();
        operators.sort();
        Ok(matches!(record.body, Body::HeaderV2 { enrollment, .. }
            if enrollment.account == account && enrollment.group == group
                && enrollment.operators == operators && enrollment.initial_native_state_sha256 == native))
    }

    /// Fixed source schemas only. This chains original bytes; it is not a semantic
    /// recovery validator and cannot turn a supplied decoded object into authority.
    pub(super) fn record_source(&mut self, value: serde_json::Value) -> Result<()> {
        let transition = match value.get("schema").and_then(|v| v.as_str()) {
            Some("receiver-enrollment.v1") => TransitionKind::Enrollment,
            Some("receiver-wire.v1") => TransitionKind::Wire,
            Some("receiver-outcome.v1") => TransitionKind::Outcome,
            Some("semantic-original.v1" | "semantic-original.v2") => TransitionKind::Original,
            Some("semantic-expired.v1") => TransitionKind::Expired,
            Some("semantic-outbound.v1") => TransitionKind::Outbound,
            Some("semantic-published.v1" | "semantic-card-complete.v1") => {
                TransitionKind::Published
            }
            Some("semantic-decision.v1") => TransitionKind::Decision,
            Some("semantic-conflict.v1" | "semantic-removal.v1") => TransitionKind::Conflict,
            Some("semantic-consumed.v1") => TransitionKind::Consumed,
            _ => return Err(Hold::Encoding),
        };
        let payload = serde_json::to_vec(&value).map_err(|_| Hold::Encoding)?;
        if payload.len() > 4 * 1024 * 1024 {
            return Err(Hold::Encoding);
        }
        let terminal = match value.get("schema").and_then(|v| v.as_str()) {
            Some("semantic-card-complete.v1") => {
                let ask_id = value
                    .get("ask_id")
                    .and_then(|v| v.as_str())
                    .ok_or(Hold::Encoding)?;
                let original_operation_sha256 = self.source_original(ask_id)?;
                Some(Body::CardComplete {
                    ask_id: ask_id.into(),
                    original_operation_sha256,
                })
            }
            Some("semantic-consumed.v1") => {
                let ask = value
                    .get("ask_id")
                    .and_then(|v| v.as_str())
                    .ok_or(Hold::Encoding)?;
                let operation = value
                    .get("operation_sha256")
                    .and_then(|v| v.as_str())
                    .ok_or(Hold::Encoding)?;
                Some(Body::Consumed {
                    key: self.source_card(ask, operation)?,
                })
            }
            _ => None,
        };
        if let Some(body) = &terminal {
            self.validate_body(body)?;
        }
        let result = (|| {
            self.write(Body::Transition {
                transition,
                payload_hex: hex::encode(payload),
            })?;
            if let Some(body) = terminal {
                self.write(body)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.latched = true;
        }
        result
    }

    fn source_original(&self, ask: &str) -> Result<String> {
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let mut reader = BufReader::new(&self.files.journal);
        let mut operation = None;
        while let Some(record) = next::<Record>(&mut reader)? {
            let Body::Transition {
                transition: TransitionKind::Original,
                payload_hex,
            } = record.body
            else {
                continue;
            };
            let value: serde_json::Value =
                serde_json::from_slice(&hex::decode(payload_hex).map_err(|_| Hold::Encoding)?)
                    .map_err(|_| Hold::Encoding)?;
            if !matches!(
                value.get("schema").and_then(|v| v.as_str()),
                Some("semantic-original.v1" | "semantic-original.v2")
            ) {
                return Err(Hold::Encoding);
            }
            let original = value.get("original").ok_or(Hold::Encoding)?;
            if original.get("ask_id").and_then(|v| v.as_str()) == Some(ask) {
                let bytes = hex::decode(
                    original
                        .get("operation")
                        .and_then(|v| v.as_str())
                        .ok_or(Hold::Encoding)?,
                )
                .map_err(|_| Hold::Encoding)?;
                if operation.is_some() || bytes.is_empty() {
                    return Err(Hold::Changed);
                }
                operation = Some(hex::encode(Sha256::digest(bytes)));
            }
        }
        operation.ok_or(Hold::Changed)
    }

    /// Return only the exact positively anchored one-use record, never a
    /// candidate sequence or a caller-created generation/card projection.
    pub(super) fn consumed_key(&self, ask: &str, operation: &str) -> Result<UseKey> {
        if self.latched {
            return Err(Hold::Latched);
        }
        let expected = self.source_card(ask, operation)?;
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let mut reader = BufReader::new(&self.files.journal);
        let mut found = false;
        while let Some(record) = next::<Record>(&mut reader)? {
            if let Body::Consumed { key } = record.body
                && key.ask_id == ask
            {
                if found || key != expected {
                    return Err(Hold::Changed);
                }
                found = true;
            }
        }
        if !found {
            return Err(Hold::Changed);
        }
        Ok(expected)
    }

    fn source_card(&self, ask: &str, operation: &str) -> Result<UseKey> {
        io((&self.files.journal).seek(SeekFrom::Start(0)))?;
        let mut reader = BufReader::new(&self.files.journal);
        let mut key = None;
        while let Some(record) = next::<Record>(&mut reader)? {
            if let Body::CardComplete {
                ask_id,
                original_operation_sha256,
            } = record.body
                && ask_id == ask
            {
                if key.is_some() || original_operation_sha256 != operation {
                    return Err(Hold::Changed);
                }
                key = Some(UseKey {
                    header_sha256: self.header_digest.clone(),
                    card_complete_sequence: record.sequence,
                    ask_id,
                    original_operation_sha256,
                });
            }
        }
        key.ok_or(Hold::Changed)
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
        match &record.body {
            Body::Header { .. } => return Err(Hold::Changed),
            Body::HeaderV2 { enrollment, .. } if record.sequence == 1 => enrollment.check()?,
            Body::HeaderV2 { .. } => return Err(Hold::Changed),
            _ if record.sequence == 1 => return Err(Hold::Changed),
            _ => (),
        }
        self.sequence = record.sequence;
        self.digest = record.sha256;
        self.anchor_digest = anchor.sha256;
        self.last_time = time;
        self.latched = false;
        Ok(())
    }

    fn validate_body(&self, body: &Body) -> Result<()> {
        match body {
            Body::Header { .. } => Err(Hold::Changed),
            Body::HeaderV2 { enrollment, .. } => {
                if self.sequence != 0 {
                    return Err(Hold::Changed);
                }
                enrollment.check()
            }
            Body::Transition { payload_hex, .. }
                if payload_hex.len() > 8 * 1024 * 1024
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
pub(super) fn valid_group(value: &str) -> bool {
    matches!(value.len(), 32 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_ask(id: &str) -> bool {
    id.len() == 4
        && id
            .bytes()
            .all(|b| b"23456789abcdefghjkmnpqrstuvwxyz".contains(&b))
}

#[cfg(test)]
#[path = "protected_recovery_tests.rs"]
pub(super) mod tests;
