//! Dormant protected-receiver source seam; not an approval or public admission API.
//! The eventual factory must own the engine, MLS state and journal under protected custody.

use crate::Engine;
use cgka_traits::{
    EngineError,
    app_event::{
        MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT,
        MARMOT_APP_EVENT_KIND_REACTION, MARMOT_APP_EVENT_KIND_REMOVE, MarmotAppEvent,
    },
    engine::{CgkaEngine, GroupEvent},
    ingest::IngestOutcome,
    storage::StorageProvider,
    transport::TransportMessage,
    types::{GroupId, MemberId, MessageId},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_WIRE: usize = 1024 * 1024;
const MAX_RECORD: usize = 4 * 1024 * 1024;

/// Evidence only. Construction is confined to the owned real-engine path.
#[derive(Debug, Serialize)]
pub(crate) struct AuthenticatedCandidate {
    sequence: u64,
    received_at_unix_ms: u128,
    group: GroupId,
    message_id: String,
    source_epoch: u64,
    sender: MemberId,
    application: MarmotAppEvent,
}

/// Non-authoritative protected-journal readback. It cannot be converted into
/// AuthenticatedCandidate; only the actual native ingest path creates evidence.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedCandidate {
    sequence: u64,
    received_at_unix_ms: u128,
    group: GroupId,
    message_id: String,
    source_epoch: u64,
    sender: MemberId,
    application: MarmotAppEvent,
}
impl RetainedCandidate {
    pub(super) fn matches_retained(
        &self,
        wire: &RetainedWire,
        projections: &[PendingApplicationProjection],
    ) -> bool {
        self.sequence == wire.sequence
            && self.received_at_unix_ms == wire.received_at_unix_ms
            && self
                .application
                .validate_sender(&hex::encode(self.sender.as_slice()))
                .is_ok()
            && projections
                .iter()
                .filter(|p| {
                    p.group == self.group
                        && hex::encode(p.message_id.as_slice()) == self.message_id
                        && p.source_epoch == self.source_epoch
                        && p.sender == self.sender
                        && self.application.encode().is_ok_and(|bytes| {
                            p.application_sha256 == hex::encode(Sha256::digest(bytes))
                        })
                })
                .count()
                == 1
    }
}

/// Complete immutable native pending identity; delivery/read/retention annotations
/// are intentionally excluded. Constructed at the actual owned ingest event seam.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingApplicationProjection {
    group: GroupId,
    message_id: MessageId,
    sender: MemberId,
    source_epoch: u64,
    payload_sha256: String,
    // Canonical semantic payload hash captured from the actual native plaintext.
    // Raw payload may contain valid noncanonical JSON; retain both bindings.
    application_sha256: String,
}
impl PendingApplicationProjection {
    pub(super) fn matches_id(&self, id: &MessageId) -> bool {
        &self.message_id == id
    }
    pub(super) fn capture(event: &GroupEvent) -> Option<Self> {
        match event {
            GroupEvent::MessageReceived {
                group_id,
                message_id,
                sender,
                epoch,
                payload,
                ..
            } => Some(Self {
                group: group_id.clone(),
                message_id: message_id.clone(),
                sender: sender.clone(),
                source_epoch: epoch.0,
                payload_sha256: hex::encode(Sha256::digest(payload)),
                application_sha256: hex::encode(Sha256::digest(
                    MarmotAppEvent::decode(payload).ok()?.encode().ok()?,
                )),
            }),
            _ => None,
        }
    }
}

/// Journal-owned wire/outcome decoding only; no external authority import API.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedWire {
    pub(super) schema: String,
    pub(super) sequence: u64,
    pub(super) received_at_unix_ms: u128,
    pub(super) wire: TransportMessage,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedOutcome {
    pub(super) schema: String,
    pub(super) sequence: u64,
    pub(super) message_id: String,
    pub(super) outcome: IngestOutcome,
    pub(super) candidate: Option<RetainedCandidate>,
    pub(super) pending_application_ids: Vec<MessageId>,
    pub(super) pending_application_projections: Vec<PendingApplicationProjection>,
    pub(super) native_merge: Option<serde_json::Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReceiverHold {
    Configuration,
    Journal,
    Capacity,
    Latched,
    Engine,
    ChangedState,
    Malformed,
}

enum ReceiverJournal {
    Fresh(File),
    #[cfg(unix)]
    Ordered(crate::protected_recovery::Journal),
}
impl ReceiverJournal {
    fn length(&self) -> Result<u64, ReceiverHold> {
        match self {
            Self::Fresh(file) => file
                .metadata()
                .map(|m| m.len())
                .map_err(|_| ReceiverHold::Journal),
            #[cfg(unix)]
            Self::Ordered(journal) => journal.length().map_err(|_| ReceiverHold::Journal),
        }
    }
}

/// No injectable engine trait, observer callback, plaintext ingress or authority deserializer.
/// No restart/reopen path: an interrupted journal requires explicit reconciliation.
pub(crate) struct ProtectedReceiver<S: StorageProvider + 'static> {
    engine: Engine<S>,
    group: GroupId,
    operators: Vec<MemberId>,
    journal: ReceiverJournal,
    sequence: u64,
    latched: bool,
}

impl<S: StorageProvider + 'static> ProtectedReceiver<S> {
    /// Private source seam, not an authenticated factory. Existing buffered events refuse.
    pub(crate) fn new(
        mut engine: Engine<S>,
        group: GroupId,
        operators: Vec<MemberId>,
        journal: File,
    ) -> Result<Self, ReceiverHold> {
        let metadata = journal.metadata().map_err(|_| ReceiverHold::Journal)?;
        if !metadata.is_file()
            || metadata.len() != 0
            || operators.is_empty()
            || operators.len() > 64
            || operators.contains(&engine.self_id())
            || !engine.drain_events().is_empty()
        {
            return Err(ReceiverHold::Configuration);
        }
        engine
            .group_authority(&group)
            .map_err(|_| ReceiverHold::Configuration)?;
        Ok(Self {
            engine,
            group,
            operators,
            journal: ReceiverJournal::Fresh(journal),
            sequence: 0,
            latched: false,
        })
    }

    /// Owned fresh join continuation. The actual native evidence is retained in
    /// the anchored chain before positively acknowledging exactly its Welcome.
    /// No production path opener or custody authority is supplied here.
    #[cfg(unix)]
    pub(super) fn from_native_join(
        mut engine: Engine<S>,
        group: GroupId,
        operators: Vec<MemberId>,
        mut journal: crate::protected_recovery::Journal,
        evidence: crate::protected_join::JoinEvidence,
    ) -> Result<Self, ReceiverHold> {
        let projection = engine
            .with_mls_group(&group, |native| {
                if !engine.receiver_group_quiet(&group, native)? {
                    return Err(EngineError::Other("receiver join not quiet".into()));
                }
                crate::protected_merge::Projection::read(native)
            })
            .map_err(|_| ReceiverHold::ChangedState)?;
        let native = hex::encode(Sha256::digest(
            serde_json::to_vec(&projection).map_err(|_| ReceiverHold::Malformed)?,
        ));
        let pending = engine
            .storage
            .list_pending_application_events()
            .map_err(|_| ReceiverHold::Engine)?;
        if operators.is_empty()
            || operators.len() > 64
            || operators.contains(&engine.self_id())
            || operators
                .iter()
                .map(|m| hex::encode(m.as_slice()))
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != operators.len()
            || evidence.group != group
            || evidence.joined != projection
            || pending.len() != 1
            || !evidence.matches_pending(&pending[0])
            || engine.events_buf.len() != 1
            || !evidence.matches_pending(&engine.events_buf[0])
            || !journal
                .binds_native(
                    &hex::encode(engine.self_id().as_slice()),
                    &hex::encode(group.as_slice()),
                    &operators
                        .iter()
                        .map(|m| hex::encode(m.as_slice()))
                        .collect::<Vec<_>>(),
                    &native,
                )
                .map_err(|_| ReceiverHold::Journal)?
        {
            return Err(ReceiverHold::ChangedState);
        }
        journal
            .retain_join(&evidence)
            .map_err(|_| ReceiverHold::Journal)?;
        engine
            .storage
            .delete_pending_application_events(std::slice::from_ref(&evidence.original_wire.id))
            .map_err(|_| ReceiverHold::Journal)?;
        engine.events_buf.clear(); // Exactly the positively matched singleton above.
        Ok(Self {
            engine,
            group,
            operators,
            journal: ReceiverJournal::Ordered(journal),
            sequence: 0,
            latched: false,
        })
    }

    /// Private fresh ordered sink; not an authenticated file opener or restart API.
    #[cfg(unix)]
    fn from_ordered(
        mut engine: Engine<S>,
        group: GroupId,
        operators: Vec<MemberId>,
        journal: crate::protected_recovery::Journal,
    ) -> Result<Self, ReceiverHold> {
        let projection = engine
            .with_mls_group(&group, crate::protected_merge::Projection::read)
            .map_err(|_| ReceiverHold::Configuration)?;
        let native = hex::encode(Sha256::digest(
            serde_json::to_vec(&projection).map_err(|_| ReceiverHold::Malformed)?,
        ));
        if operators.is_empty()
            || operators.len() > 64
            || operators.contains(&engine.self_id())
            || !engine.drain_events().is_empty()
            || !journal
                .binds_native(
                    &hex::encode(engine.self_id().as_slice()),
                    &hex::encode(group.as_slice()),
                    &operators
                        .iter()
                        .map(|m| hex::encode(m.as_slice()))
                        .collect::<Vec<_>>(),
                    &native,
                )
                .map_err(|_| ReceiverHold::Journal)?
        {
            return Err(ReceiverHold::Configuration);
        }
        engine
            .group_authority(&group)
            .map_err(|_| ReceiverHold::Configuration)?;
        Ok(Self {
            engine,
            group,
            operators,
            journal: ReceiverJournal::Ordered(journal),
            sequence: 0,
            latched: false,
        })
    }

    /// Positive plaintext reconciliation only. This does not admit a semantic
    /// factory or replay any wire. Unknown pending native state refuses before
    /// deleting anything, including unrelated welcome/lifecycle outputs.
    #[cfg(unix)]
    fn reconcile_pending_plaintext(
        engine: &mut Engine<S>,
        journal: &crate::protected_recovery::Journal,
    ) -> Result<(), ReceiverHold> {
        let pending = engine
            .storage
            .list_pending_application_events()
            .map_err(|_| ReceiverHold::Journal)?;
        let projections = pending
            .iter()
            .map(PendingApplicationProjection::capture)
            .collect::<Option<Vec<_>>>()
            .ok_or(ReceiverHold::ChangedState)?;
        journal
            .verify_pending(&projections)
            .map_err(|_| ReceiverHold::ChangedState)?;
        let ids = pending
            .iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        engine
            .storage
            .delete_pending_application_events(&ids)
            .map_err(|_| ReceiverHold::Journal)
    }

    fn checked_now(&self) -> Result<u64, ReceiverHold> {
        match &self.journal {
            #[cfg(unix)]
            ReceiverJournal::Ordered(journal) => {
                journal.checked_now().map_err(|_| ReceiverHold::Journal)
            }
            ReceiverJournal::Fresh(_) => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ReceiverHold::Journal)?
                .as_millis()
                .try_into()
                .map_err(|_| ReceiverHold::Journal),
        }
    }
    fn record(&mut self, value: impl Serialize) -> Result<(), ReceiverHold> {
        let mut bytes = serde_json::to_vec(&value).map_err(|_| ReceiverHold::Journal)?;
        if bytes.len() > MAX_RECORD {
            return Err(ReceiverHold::Capacity);
        }
        bytes.push(b'\n');
        let length = self.journal.length()?;
        if length.checked_add(bytes.len() as u64).is_none() {
            return Err(ReceiverHold::Capacity);
        }
        match &mut self.journal {
            ReceiverJournal::Fresh(file) => file
                .write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| ReceiverHold::Journal),
            #[cfg(unix)]
            ReceiverJournal::Ordered(journal) => journal
                .record_source(serde_json::from_slice(&bytes).map_err(|_| ReceiverHold::Malformed)?)
                .map_err(|_| ReceiverHold::Journal),
        }
    }

    pub(crate) async fn ingest(
        &mut self,
        wire: TransportMessage,
    ) -> Result<Option<AuthenticatedCandidate>, ReceiverHold> {
        if self.latched {
            return Err(ReceiverHold::Latched);
        }
        let encoded = serde_json::to_vec(&wire).map_err(|_| ReceiverHold::Malformed)?;
        if encoded.len() > MAX_WIRE {
            return Err(ReceiverHold::Capacity);
        }
        // Check representable file lengths before native state changes. This is
        // arithmetic validation, NOT disk reservation: a later write/fsync may
        // fail after native mutation and must HOLD without blind replay. There
        // is no lifetime journal cap or promise of available disk capacity.
        let available = self.journal.length()?;
        if available
            .checked_add(encoded.len() as u64 + MAX_RECORD as u64 + 1024)
            .is_none()
        {
            return Err(ReceiverHold::Capacity);
        }
        // Latch only once ingress may cross a durable/effect boundary.
        self.latched = true;
        let received = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReceiverHold::Journal)?
            .as_millis();
        self.sequence = self.sequence.checked_add(1).ok_or(ReceiverHold::Capacity)?;
        self.record(
            serde_json::json!({"schema":"receiver-wire.v1", "sequence":self.sequence,
            "received_at_unix_ms":received, "wire":wire}),
        )?;
        self.engine.receiver_ingress_capture = Some((wire.id.clone(), None));
        self.engine.receiver_merge_capture = Some(crate::protected_merge::Capture::for_group(
            self.group.clone(),
        ));
        let result = self.engine.ingest(wire.clone()).await;
        let content_id = self
            .engine
            .receiver_ingress_capture
            .take()
            .and_then(|(_, value)| value);
        let merge = self
            .engine
            .receiver_merge_capture
            .take()
            .ok_or(ReceiverHold::ChangedState)?;
        let outcome = result.map_err(|_| ReceiverHold::Engine)?;
        if !matches!(
            outcome,
            IngestOutcome::Processed
                | IngestOutcome::Ignored { .. }
                | IngestOutcome::Rejected { .. }
        ) {
            return Err(ReceiverHold::ChangedState);
        }
        let mut candidate = None;
        let mut pending_ids = Vec::new();
        let mut pending_projections = Vec::new();
        for event in self.engine.drain_events() {
            let projection = PendingApplicationProjection::capture(&event);
            match event {
                GroupEvent::MessageReceived {
                    group_id,
                    message_id,
                    sender,
                    epoch,
                    payload,
                    ..
                } if group_id == self.group && Some(&message_id) == content_id.as_ref() => {
                    pending_ids.push(message_id.clone());
                    pending_projections.push(projection.ok_or(ReceiverHold::ChangedState)?);
                    // Eligibility derives from the authenticated MLS credential. An
                    // unrelated member's malformed inner event is not operator input.
                    if sender == self.engine.self_id() || !self.operators.contains(&sender) {
                        continue;
                    }
                    let app =
                        MarmotAppEvent::decode(&payload).map_err(|_| ReceiverHold::Malformed)?;
                    app.validate_sender(&hex::encode(sender.as_slice()))
                        .map_err(|_| ReceiverHold::Malformed)?;
                    if !matches!(
                        app.kind,
                        MARMOT_APP_EVENT_KIND_CHAT
                            | MARMOT_APP_EVENT_KIND_REACTION
                            | MARMOT_APP_EVENT_KIND_DELETE
                            | MARMOT_APP_EVENT_KIND_EDIT
                            | MARMOT_APP_EVENT_KIND_REMOVE
                    ) {
                        continue;
                    }
                    if candidate.is_some() {
                        return Err(ReceiverHold::ChangedState);
                    }
                    candidate = Some(AuthenticatedCandidate {
                        sequence: self.sequence,
                        received_at_unix_ms: received,
                        group: group_id,
                        message_id: hex::encode(message_id.as_slice()),
                        source_epoch: epoch.0,
                        sender,
                        application: app,
                    });
                }
                GroupEvent::EpochChanged { group_id, from, to }
                    if content_id.as_ref().is_some_and(|content| {
                        merge.matches_epoch(&group_id, from.0, to.0, content)
                    }) && group_id == self.group =>
                {
                    let current = self
                        .engine
                        .group_authority(&self.group)
                        .map_err(|_| ReceiverHold::ChangedState)?;
                    if current.lifecycle != cgka_traits::GroupLifecycleState::Stable
                        || !self.engine.auto_publish_buf.is_empty()
                        || !self.engine.auto_proposal_buf.is_empty()
                        || self
                            .engine
                            .has_pending_convergence_inputs(&self.group)
                            .map_err(|_| ReceiverHold::ChangedState)?
                        || self
                            .engine
                            .has_pending_canonical_applications(&self.group)
                            .map_err(|_| ReceiverHold::ChangedState)?
                    {
                        return Err(ReceiverHold::ChangedState);
                    }
                }
                // Conservatively refuse state changes, reorgs and delayed messages. This
                // slice does not authenticate a prior wire using the current wire's record.
                _ => return Err(ReceiverHold::ChangedState),
            }
        }
        self.record(serde_json::json!({"schema":"receiver-outcome.v1", "sequence":self.sequence,
            "message_id":hex::encode(wire.id.as_slice()), "outcome":outcome, "candidate":candidate,"pending_application_ids":pending_ids,"pending_application_projections":pending_projections,"native_merge":merge.direct}))?;
        // Native pending plaintext may be dropped only after the complete durable
        // receiver projection exists. Deletion is idempotent; failure stays held.
        self.engine
            .storage
            .delete_pending_application_events(&pending_ids)
            .map_err(|_| ReceiverHold::Journal)?;
        self.latched = false;
        Ok(candidate)
    }
}

#[cfg(test)]
#[path = "protected_receiver_tests.rs"]
mod tests;

/// Called only at native peel/rebind, never from caller-supplied decoded events.
pub(crate) fn capture_receiver_content(
    capture: &mut Option<(MessageId, Option<MessageId>)>,
    outer: &MessageId,
    content: &MessageId,
) -> Result<(), EngineError> {
    if let Some((expected, captured)) = capture
        && expected == outer
    {
        if captured
            .as_ref()
            .is_some_and(|previous| previous != content)
        {
            return Err(EngineError::Other(
                "receiver content binding changed".into(),
            ));
        }
        *captured = Some(content.clone());
    }
    Ok(())
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[path = "protected_semantic.rs"]
mod semantic;

#[cfg(unix)]
#[path = "protected_reopen.rs"]
mod reopen;
