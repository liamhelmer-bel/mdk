//! Disposable derived disk index, rebuilt only from an owned anchored journal.
//! It is not an authority import or an independent anti-rollback anchor. Full
//! originals remain in the journal; only <=100 unanswered projections stay in RAM.
use super::{ReceiverHold, digest, valid_ask_id};
use crate::protected_recovery::{Journal, SourceRecord};
use cgka_traits::{TransportEndpoint, TransportPublishReport, transport::TransportMessage};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
};

type Result<T> = std::result::Result<T, ReceiverHold>;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Disposition {
    Awaiting,
    Approved,
    Denied,
    Conflicted,
    Expired,
    Consumed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ask {
    pub(super) id: String,
    pub(super) original_sequence: u64,
    pub(super) complete_sequence: Option<u64>,
    pub(super) decision_sequence: Option<u64>,
    pub(super) original_sha256: String,
    pub(super) packet_sha256: String,
    pub(super) request_sha256: String,
    pub(super) cards_sha256: String,
    pub(super) policy_sha256: String,
    pub(super) expiry: u64,
    pub(super) app_ids: Vec<String>,
    pub(super) disposition: Disposition,
    pub(super) consumed: bool,
    pub(super) conflicted: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    ask: String,
    decision_owner: Option<serde_json::Value>,
}
struct Building {
    ask: Ask,
    next_part: usize,
    outbound: Option<TransportMessage>,
    complete: bool,
    parts: usize,
}
/// Only source-derived fixed namespaces. Caller strings never form paths.
#[derive(Clone, Copy)]
enum Space {
    Ask,
    Target,
    Candidate,
    Removal,
    Checkpoint,
}
impl Space {
    fn name(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Target => "target",
            Self::Candidate => "candidate",
            Self::Removal => "removal",
            Self::Checkpoint => "checkpoint",
        }
    }
}
struct Disk {
    directory: File,
}
impl Disk {
    fn fresh(directory: File) -> Result<Self> {
        let meta = directory.metadata().map_err(|_| ReceiverHold::Journal)?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 {
            return Err(ReceiverHold::Configuration);
        }
        directory
            .try_lock()
            .map_err(|_| ReceiverHold::ChangedState)?;
        let disk = Self { directory };
        if std::fs::read_dir(disk.path())
            .map_err(|_| ReceiverHold::Journal)?
            .next()
            .is_some()
        {
            return Err(ReceiverHold::Configuration);
        }
        Ok(disk)
    }
    fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }
    fn key(&self, space: Space, key: &str) -> PathBuf {
        self.path()
            .join(digest(format!("{}\0{}", space.name(), key).as_bytes()))
    }
    fn read<T: DeserializeOwned>(&self, space: Space, key: &str) -> Result<Option<T>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.key(space, key)); // Architecture-correct Linux O_NOFOLLOW.
        let mut file = match file {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ReceiverHold::Journal),
        };
        check_file(&file)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| ReceiverHold::Journal)?;
        if bytes.len() > 8192 {
            return Err(ReceiverHold::ChangedState);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| ReceiverHold::ChangedState)
    }
    fn put(&self, space: Space, key: &str, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|_| ReceiverHold::Malformed)?;
        if bytes.len() > 8192 {
            return Err(ReceiverHold::Capacity);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.key(space, key))
            .map_err(|_| ReceiverHold::Journal)?;
        check_file(&file)?;
        file.set_len(0)
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .map_err(|_| ReceiverHold::Journal)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| self.directory.sync_all())
            .map_err(|_| ReceiverHold::Journal)
    }
    fn unique(&self, space: Space, key: &str, value: &impl Serialize) -> Result<()> {
        if self.read::<serde_json::Value>(space, key)?.is_some() {
            return Err(ReceiverHold::ChangedState);
        }
        self.put(space, key, value)
    }
}
fn check_file(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|_| ReceiverHold::Journal)?;
    if !m.is_file() || m.mode() & 0o077 != 0 || m.nlink() != 1 {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    sequence: u64,
    sha256: String,
    offset: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateReference {
    sequence: u64,
    sha256: String,
}
pub(super) struct Catalog {
    disk: Disk,
    pub(super) unanswered: BTreeMap<String, Ask>,
    checkpoint: Checkpoint,
    pub(super) high_water_unanswered: usize,
    pub(super) receiver_sequence: u64,
    pub(super) unprojected: Option<serde_json::Value>,
}
impl Catalog {
    /// The directory must be a new protected derived-cache directory. A failed
    /// build never produces a usable checkpoint; existing directories are refused.
    pub(super) fn rebuild(
        journal: &Journal,
        directory: File,
        policy: &str,
        endpoints: &[TransportEndpoint],
    ) -> Result<Self> {
        Self::rebuild_inner(journal, directory, policy, endpoints, false)
    }
    pub(super) fn rebuild_for_reopen(
        journal: &Journal,
        directory: File,
        policy: &str,
        endpoints: &[TransportEndpoint],
    ) -> Result<Self> {
        Self::rebuild_inner(journal, directory, policy, endpoints, true)
    }
    fn rebuild_inner(
        journal: &Journal,
        directory: File,
        policy: &str,
        endpoints: &[TransportEndpoint],
        recover_final: bool,
    ) -> Result<Self> {
        let mut builder = Builder {
            disk: Disk::fresh(directory)?,
            journal,
            policy,
            endpoints,
            building: BTreeMap::new(),
            receiver_sequence: 0,
            wire: None,
            high_water: 0,
            control: None,
            pending_candidate: None,
            removal_retained: false,
        };
        let mut cursor = journal.source_cursor().map_err(|_| ReceiverHold::Journal)?;
        while let Some(record) = cursor.next().map_err(|_| ReceiverHold::Journal)? {
            builder.apply(&record)?;
        }
        let offset = cursor.offset();
        builder.finish(offset, recover_final)
    }
    /// Continue only from our owned, verified checkpoint. A partial failed
    /// projection leaves no usable Catalog; the owner remains held.
    pub(super) fn advance(
        self,
        journal: &Journal,
        policy: &str,
        endpoints: &[TransportEndpoint],
    ) -> Result<Self> {
        self.checkpoint_file()?;
        let mut cursor = journal
            .source_after(
                self.checkpoint.sequence,
                self.checkpoint.sha256,
                self.checkpoint.offset,
            )
            .map_err(|_| ReceiverHold::Journal)?;
        let mut builder = Builder {
            disk: self.disk,
            journal,
            policy,
            endpoints,
            building: self
                .unanswered
                .into_iter()
                .map(|(id, ask)| {
                    (
                        id,
                        Building {
                            ask,
                            next_part: 0,
                            outbound: None,
                            complete: true,
                            parts: 0,
                        },
                    )
                })
                .collect(),
            receiver_sequence: self.receiver_sequence,
            wire: None,
            high_water: self.high_water_unanswered,
            control: None,
            pending_candidate: self.unprojected,
            removal_retained: false,
        };
        while let Some(record) = cursor.next().map_err(|_| ReceiverHold::Journal)? {
            builder.apply(&record)?;
        }
        builder.finish(cursor.offset(), false)
    }
    fn checkpoint_file(&self) -> Result<()> {
        let actual: Checkpoint = self
            .disk
            .read(Space::Checkpoint, "head")?
            .ok_or(ReceiverHold::ChangedState)?;
        if actual.sequence != self.checkpoint.sequence
            || actual.sha256 != self.checkpoint.sha256
            || actual.offset != self.checkpoint.offset
        {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(())
    }
    pub(super) fn retained_ask(&self, id: &str) -> Result<Option<Ask>> {
        self.checkpoint_file()?;
        self.disk.read(Space::Ask, id)
    }
    pub(super) fn retained_candidate(&self, id: &str) -> Result<bool> {
        self.checkpoint_file()?;
        Ok(self
            .disk
            .read::<CandidateReference>(Space::Candidate, id)?
            .is_some())
    }
    pub(super) fn check_retained_candidate(
        &self,
        journal: &Journal,
        candidate: &serde_json::Value,
    ) -> Result<()> {
        self.checkpoint_file()?;
        validate_candidate(&self.disk, journal, candidate)
    }
    pub(super) fn retained_target(&self, id: &str) -> Result<Option<String>> {
        self.checkpoint_file()?;
        Ok(self.disk.read::<Target>(Space::Target, id)?.map(|t| t.ask))
    }
    pub(super) fn relevant(&self, candidate: &serde_json::Value) -> Result<Vec<String>> {
        self.checkpoint_file()?;
        relevant_asks(&self.disk, candidate)
    }
    pub(super) fn retained_removal(&self, sender: &serde_json::Value, id: &str) -> Result<bool> {
        self.checkpoint_file()?;
        for scope in [sender.clone(), serde_json::Value::Null] {
            if self
                .disk
                .read::<u64>(
                    Space::Removal,
                    &serde_json::to_string(&(scope, id.to_ascii_lowercase()))
                        .map_err(|_| ReceiverHold::Malformed)?,
                )?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn current(&self, journal: &Journal) -> Result<()> {
        if journal.checkpoint() != (self.checkpoint.sequence, self.checkpoint.sha256.clone()) {
            return Err(ReceiverHold::ChangedState);
        }
        let actual: Checkpoint = self
            .disk
            .read(Space::Checkpoint, "head")?
            .ok_or(ReceiverHold::ChangedState)?;
        if (actual.sequence, actual.sha256)
            != (self.checkpoint.sequence, self.checkpoint.sha256.clone())
        {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(())
    }
    pub(super) fn ask(&self, journal: &Journal, id: &str) -> Result<Option<Ask>> {
        self.current(journal)?;
        self.disk.read(Space::Ask, id)
    }
    pub(super) fn candidate_seen(&self, journal: &Journal, id: &str) -> Result<bool> {
        self.current(journal)?;
        Ok(self
            .disk
            .read::<CandidateReference>(Space::Candidate, id)?
            .is_some())
    }
    pub(super) fn target(&self, journal: &Journal, id: &str) -> Result<Option<String>> {
        self.current(journal)?;
        Ok(self.disk.read::<Target>(Space::Target, id)?.map(|t| t.ask))
    }
    pub(super) fn removed(
        &self,
        journal: &Journal,
        sender: &serde_json::Value,
        id: &str,
    ) -> Result<bool> {
        self.current(journal)?;
        for scope in [sender.clone(), serde_json::Value::Null] {
            if self
                .disk
                .read::<u64>(
                    Space::Removal,
                    &serde_json::to_string(&(scope, id.to_ascii_lowercase()))
                        .map_err(|_| ReceiverHold::Malformed)?,
                )?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
struct Builder<'a> {
    disk: Disk,
    journal: &'a Journal,
    policy: &'a str,
    endpoints: &'a [TransportEndpoint],
    building: BTreeMap<String, Building>,
    receiver_sequence: u64,
    wire: Option<super::super::RetainedWire>,
    high_water: usize,
    control: Option<(String, bool, u64)>,
    pending_candidate: Option<serde_json::Value>,
    removal_retained: bool,
}
impl Builder<'_> {
    fn apply(&mut self, record: &SourceRecord) -> Result<()> {
        if let Some((id, consumed, source_sequence)) = self.control.take() {
            let mut ask = self
                .disk
                .read::<Ask>(Space::Ask, &id)?
                .ok_or(ReceiverHold::ChangedState)?;
            if record.sequence != source_sequence + 1 {
                return Err(ReceiverHold::ChangedState);
            }
            if consumed {
                let key = &record.body["key"];
                if record.body["kind"] != "consumed"
                    || key["header_sha256"] != self.journal.header_hash()
                    || key["ask_id"] != id
                    || key["original_operation_sha256"] != ask.original_sha256
                    || key["card_complete_sequence"].as_u64() != ask.complete_sequence
                {
                    return Err(ReceiverHold::ChangedState);
                }
                ask.disposition = Disposition::Consumed;
                ask.consumed = true;
            } else {
                if record.body["kind"] != "card-complete"
                    || record.body["ask_id"] != id
                    || record.body["original_operation_sha256"] != ask.original_sha256
                {
                    return Err(ReceiverHold::ChangedState);
                }
                ask.complete_sequence = Some(record.sequence);
                self.building
                    .get_mut(&id)
                    .ok_or(ReceiverHold::ChangedState)?
                    .ask
                    .complete_sequence = Some(record.sequence);
            }
            self.disk.put(Space::Ask, &id, &ask)?;
            return Ok(());
        }
        if record.body["kind"] == "header" && record.sequence == 1 {
            return Ok(());
        }
        if record.body["kind"] != "source" {
            return Err(ReceiverHold::ChangedState);
        }
        let v = &record.body["value"];
        let schema = text(v, "schema")?;
        match schema {
            "receiver-enrollment.v1" => Ok(()),
            "receiver-wire.v1" => self.wire(v),
            "receiver-outcome.v1" => self.outcome(v, record),
            "semantic-original.v2" => self.original(v, record),
            "semantic-outbound.v1" => self.outbound(v),
            "semantic-published.v1" => self.published(v),
            "semantic-card-complete.v1" => self.complete(v, record),
            "semantic-decision.v1" => self.decision(v, record),
            "semantic-removal.v1" => self.removal(v, record),
            "semantic-conflict.v1" => self.conflict(v),
            "semantic-expired.v1" => self.expired(v, record),
            "semantic-consumed.v1" => self.consumed(v, record),
            _ => Err(ReceiverHold::ChangedState), // Never promote legacy expiry-less histories.
        }
    }
    fn wire(&mut self, v: &serde_json::Value) -> Result<()> {
        self.finish_candidate()?;
        let next: super::super::RetainedWire = decode(v)?;
        if self.wire.is_some() || next.sequence != self.receiver_sequence + 1 {
            return Err(ReceiverHold::ChangedState);
        }
        self.wire = Some(next);
        Ok(())
    }

    fn outcome(&mut self, v: &serde_json::Value, record: &SourceRecord) -> Result<()> {
        let outcome: super::super::RetainedOutcome = decode(v)?;
        let original = self.wire.take().ok_or(ReceiverHold::ChangedState)?;
        if outcome.sequence != original.sequence
            || outcome.message_id != hex::encode(original.wire.id.as_slice())
            || !matches!(
                outcome.outcome,
                cgka_traits::ingest::IngestOutcome::Processed
                    | cgka_traits::ingest::IngestOutcome::Ignored { .. }
                    | cgka_traits::ingest::IngestOutcome::Rejected { .. }
            )
        {
            return Err(ReceiverHold::ChangedState);
        }
        if let Some(candidate) = &outcome.candidate {
            if !candidate.matches_retained(&original, &outcome.pending_application_projections) {
                return Err(ReceiverHold::ChangedState);
            }
            self.disk.unique(
                Space::Candidate,
                &candidate.message_id,
                &CandidateReference {
                    sequence: record.sequence,
                    sha256: digest(
                        &serde_json::to_vec(&v["candidate"])
                            .map_err(|_| ReceiverHold::Malformed)?,
                    ),
                },
            )?;
            self.pending_candidate = Some(v["candidate"].clone());
            self.removal_retained = false;
        }
        self.receiver_sequence = outcome.sequence;
        Ok(())
    }

    fn original(&mut self, v: &serde_json::Value, record: &SourceRecord) -> Result<()> {
        self.finish_candidate()?;
        let o = &v["original"];
        let id = text(o, "ask_id")?.to_owned();
        let expiry = v["expires_at_unix_ms"]
            .as_u64()
            .ok_or(ReceiverHold::Malformed)?;
        if !valid_ask_id(&id)
            || self.building.len() >= 100
            || text(v, "policy_sha256")? != self.policy
            || expiry <= checked_at(v, record)?
            || self.disk.read::<Ask>(Space::Ask, &id)?.is_some()
        {
            return Err(ReceiverHold::ChangedState);
        }
        let chunks: Vec<String> = decode(&o["card_chunks"])?;
        if chunks.is_empty()
            || chunks.len() > 16
            || chunks.iter().any(|s| s.is_empty() || s.len() > 24000)
        {
            return Err(ReceiverHold::Malformed);
        }
        let ask = Ask {
            id: id.clone(),
            original_sequence: record.sequence,
            complete_sequence: None,
            decision_sequence: None,
            original_sha256: hex_digest(o, "operation")?,
            packet_sha256: hex_digest(o, "operation_canonical")?,
            request_sha256: hex_digest(o, "original_request")?,
            cards_sha256: digest(
                &serde_json::to_vec(&chunks).map_err(|_| ReceiverHold::Malformed)?,
            ),
            policy_sha256: self.policy.into(),
            expiry,
            app_ids: vec![],
            disposition: Disposition::Awaiting,
            consumed: false,
            conflicted: false,
        };
        self.disk.unique(Space::Ask, &id, &ask)?;
        self.building.insert(
            id,
            Building {
                ask,
                next_part: 0,
                outbound: None,
                complete: false,
                parts: chunks.len(),
            },
        );
        self.high_water = self.high_water.max(self.building.len());
        Ok(())
    }

    fn outbound(&mut self, v: &serde_json::Value) -> Result<()> {
        let id = text(v, "ask_id")?;
        let b = self
            .building
            .get_mut(id)
            .ok_or(ReceiverHold::ChangedState)?;
        let part = v["part"].as_u64().ok_or(ReceiverHold::Malformed)? as usize;
        let app = text(v, "app_event_id")?.to_owned();
        if b.complete
            || b.outbound.is_some()
            || part != b.next_part
            || !cgka_traits::reporting::event_id_is_valid(&app)
        {
            return Err(ReceiverHold::ChangedState);
        }
        self.disk.unique(
            Space::Target,
            &app,
            &Target {
                ask: id.into(),
                decision_owner: None,
            },
        )?;
        b.ask.app_ids.push(app);
        b.outbound = Some(decode(&v["wire"])?);
        Ok(())
    }

    fn published(&mut self, v: &serde_json::Value) -> Result<()> {
        let id = text(v, "ask_id")?;
        let b = self
            .building
            .get_mut(id)
            .ok_or(ReceiverHold::ChangedState)?;
        let outbound = b.outbound.take().ok_or(ReceiverHold::ChangedState)?;
        let report: TransportPublishReport = decode(&v["report"])?;
        if v["part"].as_u64() != Some(b.next_part as u64)
            || report.message_id != outbound.id
            || report.required_acks != 1
            || !report.met_required_acks()
            || report
                .accepted
                .iter()
                .any(|r| !self.endpoints.contains(&r.endpoint))
            || report
                .accepted
                .iter()
                .map(|r| &r.endpoint)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != report.accepted.len()
        {
            return Err(ReceiverHold::ChangedState);
        }
        b.next_part += 1;
        Ok(())
    }

    fn complete(&mut self, v: &serde_json::Value, record: &SourceRecord) -> Result<()> {
        let id = text(v, "ask_id")?;
        let b = self
            .building
            .get_mut(id)
            .ok_or(ReceiverHold::ChangedState)?;
        let app_ids: Vec<String> = decode(&v["app_ids"])?;
        if b.complete
            || b.outbound.is_some()
            || b.next_part != b.parts
            || app_ids != b.ask.app_ids
            || text(v, "policy_sha256")? != self.policy
        {
            return Err(ReceiverHold::ChangedState);
        }
        b.complete = true;
        self.disk.put(Space::Ask, id, &b.ask)?;
        self.control = Some((id.into(), false, record.sequence));
        Ok(())
    }

    fn decision(&mut self, v: &serde_json::Value, record: &SourceRecord) -> Result<()> {
        let receipt = &v["receipt"];
        let id = text(receipt, "ask_id")?;
        let mut b = self.building.remove(id).ok_or(ReceiverHold::ChangedState)?;
        let candidate = &receipt["authenticated_candidate"];
        validate_candidate(&self.disk, self.journal, candidate)?;
        if !b.complete
            || b.ask.complete_sequence.is_none()
            || text(receipt, "operation_sha256")? != b.ask.original_sha256
            || text(receipt, "packet_sha256")? != b.ask.packet_sha256
            || text(receipt, "request_sha256")? != b.ask.request_sha256
            || text(receipt, "cards_sha256")? != b.ask.cards_sha256
            || text(receipt, "policy_sha256")? != self.policy
            || receipt["operator"] != candidate["sender"]
            || receipt["sequence"] != candidate["sequence"]
        {
            return Err(ReceiverHold::ChangedState);
        }
        b.ask.disposition = match text(receipt, "decision")? {
            "Approve" => Disposition::Approved,
            "Deny" => Disposition::Denied,
            _ => return Err(ReceiverHold::Malformed),
        };
        b.ask.decision_sequence = Some(record.sequence);
        self.projected(candidate)?;
        self.disk.unique(
            Space::Target,
            text(&candidate["application"], "id")?,
            &Target {
                ask: id.into(),
                decision_owner: Some(candidate["sender"].clone()),
            },
        )?;
        self.disk.put(Space::Ask, id, &b.ask)?;
        Ok(())
    }

    fn removal(&mut self, v: &serde_json::Value, record: &SourceRecord) -> Result<()> {
        let candidate = &v["authenticated_candidate"];
        validate_candidate(&self.disk, self.journal, candidate)?;
        if self.pending_candidate.as_ref() != Some(candidate) {
            return Err(ReceiverHold::ChangedState);
        }
        self.removal_retained = true;
        let app = &candidate["application"];
        let kind = app["kind"].as_u64().ok_or(ReceiverHold::Malformed)?;
        if ![
            cgka_traits::app_event::MARMOT_APP_EVENT_KIND_DELETE,
            cgka_traits::app_event::MARMOT_APP_EVENT_KIND_EDIT,
            cgka_traits::app_event::MARMOT_APP_EVENT_KIND_REMOVE,
        ]
        .contains(&kind)
        {
            return Err(ReceiverHold::Malformed);
        }
        let scope = if kind == cgka_traits::app_event::MARMOT_APP_EVENT_KIND_REMOVE {
            serde_json::Value::Null
        } else {
            candidate["sender"].clone()
        };
        for tag in app["tags"].as_array().ok_or(ReceiverHold::Malformed)? {
            if tag[0] == "e"
                && let Some(target) = tag[1].as_str()
            {
                self.disk.put(
                    Space::Removal,
                    &serde_json::to_string(&(scope.clone(), target.to_ascii_lowercase()))
                        .map_err(|_| ReceiverHold::Malformed)?,
                    &record.sequence,
                )?;
            }
        }
        Ok(())
    }

    fn conflict(&mut self, v: &serde_json::Value) -> Result<()> {
        validate_candidate(&self.disk, self.journal, &v["authenticated_candidate"])?;
        self.projected(&v["authenticated_candidate"])?;
        for id in v["ask_ids"].as_array().ok_or(ReceiverHold::Malformed)? {
            let id = id.as_str().ok_or(ReceiverHold::Malformed)?;
            let mut ask = self
                .disk
                .read::<Ask>(Space::Ask, id)?
                .ok_or(ReceiverHold::ChangedState)?;
            if ask.complete_sequence.is_none() {
                return Err(ReceiverHold::ChangedState);
            }
            ask.conflicted = true;
            if !ask.consumed {
                ask.disposition = Disposition::Conflicted;
            }
            self.disk.put(Space::Ask, id, &ask)?;
            self.building.remove(id);
        }
        Ok(())
    }

    fn expired(&mut self, v: &serde_json::Value, record: &SourceRecord) -> Result<()> {
        let id = text(v, "ask_id")?;
        let mut ask = self
            .disk
            .read::<Ask>(Space::Ask, id)?
            .ok_or(ReceiverHold::ChangedState)?;
        let at = v["at_unix_ms"].as_u64().ok_or(ReceiverHold::Malformed)?;
        if ask.complete_sequence.is_none()
            || !matches!(
                ask.disposition,
                Disposition::Awaiting | Disposition::Approved
            )
            || ask.consumed
            || ask.conflicted
            || at < ask.expiry
            || at > record.local_unix_ms
        {
            return Err(ReceiverHold::ChangedState);
        }
        ask.disposition = Disposition::Expired;
        self.disk.put(Space::Ask, id, &ask)?;
        self.building.remove(id);
        Ok(())
    }

    fn consumed(&mut self, v: &serde_json::Value, record: &SourceRecord) -> Result<()> {
        let id = text(v, "ask_id")?;
        let ask = self
            .disk
            .read::<Ask>(Space::Ask, id)?
            .ok_or(ReceiverHold::ChangedState)?;
        if ask.disposition != Disposition::Approved
            || text(v, "operation_sha256")? != ask.original_sha256
            || checked_at(v, record)? >= ask.expiry
        {
            return Err(ReceiverHold::ChangedState);
        }
        self.control = Some((id.into(), true, record.sequence));
        Ok(())
    }
    fn projected(&mut self, candidate: &serde_json::Value) -> Result<()> {
        if self.pending_candidate.as_ref() != Some(candidate) {
            return Err(ReceiverHold::ChangedState);
        }
        self.pending_candidate = None;
        Ok(())
    }
    /// An authenticated relevant candidate without its durable semantic projection
    /// cannot leave an older approval usable. No native replay or invented reply.
    fn finish_candidate(&mut self) -> Result<()> {
        let Some(candidate) = self.pending_candidate.take() else {
            return Ok(());
        };
        let app = &candidate["application"];
        let kind = app["kind"].as_u64().ok_or(ReceiverHold::Malformed)?;
        if [
            cgka_traits::app_event::MARMOT_APP_EVENT_KIND_DELETE,
            cgka_traits::app_event::MARMOT_APP_EVENT_KIND_EDIT,
            cgka_traits::app_event::MARMOT_APP_EVENT_KIND_REMOVE,
        ]
        .contains(&kind)
            && !self.removal_retained
        {
            return Err(ReceiverHold::ChangedState);
        }
        if !relevant_asks(&self.disk, &candidate)?.is_empty() {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(())
    }
    fn finish(mut self, offset: u64, recover_final: bool) -> Result<Catalog> {
        let unprojected = if recover_final {
            self.pending_candidate.take()
        } else {
            None
        };
        self.finish_candidate()?;
        if self.wire.is_some()
            || self.control.is_some()
            || self
                .building
                .values()
                .any(|b| !b.complete || b.outbound.is_some() || b.ask.complete_sequence.is_none())
        {
            return Err(ReceiverHold::ChangedState);
        }
        let (sequence, sha256) = self.journal.checkpoint();
        let checkpoint = Checkpoint {
            sequence,
            sha256,
            offset,
        };
        self.disk.put(Space::Checkpoint, "head", &checkpoint)?;
        Ok(Catalog {
            disk: self.disk,
            unanswered: self
                .building
                .into_iter()
                .map(|(id, b)| (id, b.ask))
                .collect(),
            checkpoint,
            high_water_unanswered: self.high_water,
            receiver_sequence: self.receiver_sequence,
            unprojected,
        })
    }
}
fn relevant_asks(disk: &Disk, candidate: &serde_json::Value) -> Result<Vec<String>> {
    use cgka_traits::app_event::{
        MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT,
        MARMOT_APP_EVENT_KIND_REMOVE,
    };
    let app = &candidate["application"];
    let kind = app["kind"].as_u64().ok_or(ReceiverHold::Malformed)?;
    let mut ids = std::collections::BTreeSet::new();
    for tag in app["tags"].as_array().ok_or(ReceiverHold::Malformed)? {
        if tag[0] != "e" {
            continue;
        }
        let Some(id) = tag[1].as_str() else { continue };
        let Some(target) = disk.read::<Target>(Space::Target, &id.to_ascii_lowercase())? else {
            continue;
        };
        if target.decision_owner.as_ref().is_some_and(|owner| {
            ![
                MARMOT_APP_EVENT_KIND_DELETE,
                MARMOT_APP_EVENT_KIND_EDIT,
                MARMOT_APP_EVENT_KIND_REMOVE,
            ]
            .contains(&kind)
                || (kind != MARMOT_APP_EVENT_KIND_REMOVE && owner != &candidate["sender"])
        }) {
            continue;
        }
        if disk
            .read::<Ask>(Space::Ask, &target.ask)?
            .is_some_and(|a| a.disposition != Disposition::Expired)
        {
            ids.insert(target.ask);
        }
    }
    if kind == MARMOT_APP_EVENT_KIND_CHAT {
        let mut words = text(app, "content")?.split_whitespace();
        if words.next() == Some("!answer")
            && let Some(id) = words.next()
        {
            let id = id.to_ascii_lowercase();
            if disk
                .read::<Ask>(Space::Ask, &id)?
                .is_some_and(|a| a.disposition != Disposition::Expired)
            {
                ids.insert(id);
            }
        }
    }
    Ok(ids.into_iter().collect())
}
fn text<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or(ReceiverHold::Malformed)
}
fn decode<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T> {
    serde_json::from_value(value.clone()).map_err(|_| ReceiverHold::Malformed)
}
fn hex_digest(value: &serde_json::Value, key: &str) -> Result<String> {
    let bytes = hex::decode(text(value, key)?).map_err(|_| ReceiverHold::Malformed)?;
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err(ReceiverHold::Malformed);
    }
    Ok(digest(&bytes))
}
fn validate_candidate(disk: &Disk, journal: &Journal, candidate: &serde_json::Value) -> Result<()> {
    let retained = disk
        .read::<CandidateReference>(Space::Candidate, text(candidate, "message_id")?)?
        .ok_or(ReceiverHold::ChangedState)?;
    let source = journal
        .source_at(retained.sequence)
        .map_err(|_| ReceiverHold::Journal)?;
    if source.body["value"]["schema"] != "receiver-outcome.v1"
        || &source.body["value"]["candidate"] != candidate
        || retained.sha256
            != digest(&serde_json::to_vec(candidate).map_err(|_| ReceiverHold::Malformed)?)
    {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(())
}

#[cfg(test)]
#[path = "protected_catalog_tests.rs"]
mod tests;

// Source-owned clock observation retained with the transition. Append/fsync may
// finish later; replay must use the same actual authorization check, not a new
// write timestamp. Legacy records without this field keep the stricter old rule.
fn checked_at(v: &serde_json::Value, record: &SourceRecord) -> Result<u64> {
    let at = match v.get("checked_at_unix_ms") {
        Some(value) => value.as_u64().ok_or(ReceiverHold::Malformed)?,
        None => record.local_unix_ms,
    };
    if at > record.local_unix_ms {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(at)
}
