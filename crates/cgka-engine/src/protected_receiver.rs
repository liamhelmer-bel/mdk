//! Dormant protected-receiver source seam; not an approval or public admission API.
//! The eventual factory must own the engine, MLS state and journal under protected custody.

use crate::Engine;
use cgka_traits::{
    EngineError,
    app_event::{MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent},
    engine::{CgkaEngine, GroupEvent},
    ingest::IngestOutcome,
    storage::StorageProvider,
    transport::TransportMessage,
    types::{GroupId, MemberId, MessageId},
};
use serde::Serialize;
use std::{
    fs::File,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_WIRE: usize = 1024 * 1024;
const MAX_RECORD: usize = 4 * 1024 * 1024;
const MAX_JOURNAL: u64 = 32 * 1024 * 1024;

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

/// No injectable engine trait, observer callback, plaintext ingress or authority deserializer.
/// No restart/reopen path: an interrupted journal requires explicit reconciliation.
pub(crate) struct ProtectedReceiver<S: StorageProvider + 'static> {
    engine: Engine<S>,
    group: GroupId,
    operators: Vec<MemberId>,
    journal: File,
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
            journal,
            sequence: 0,
            latched: false,
        })
    }

    fn record(&mut self, value: impl Serialize) -> Result<(), ReceiverHold> {
        let mut bytes = serde_json::to_vec(&value).map_err(|_| ReceiverHold::Journal)?;
        if bytes.len() > MAX_RECORD {
            return Err(ReceiverHold::Capacity);
        }
        bytes.push(b'\n');
        let length = self
            .journal
            .metadata()
            .map_err(|_| ReceiverHold::Journal)?
            .len();
        if length
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > MAX_JOURNAL)
        {
            return Err(ReceiverHold::Capacity);
        }
        self.journal
            .write_all(&bytes)
            .and_then(|_| self.journal.sync_all())
            .map_err(|_| ReceiverHold::Journal)
    }

    pub(crate) async fn ingest(
        &mut self,
        wire: TransportMessage,
    ) -> Result<Option<AuthenticatedCandidate>, ReceiverHold> {
        if self.latched {
            return Err(ReceiverHold::Latched);
        }
        // Latch before any fallible effect; only a fully journalled outcome clears it.
        self.latched = true;
        let encoded = serde_json::to_vec(&wire).map_err(|_| ReceiverHold::Malformed)?;
        if encoded.len() > MAX_WIRE {
            return Err(ReceiverHold::Capacity);
        }
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
        let result = self.engine.ingest(wire.clone()).await;
        let content_id = self
            .engine
            .receiver_ingress_capture
            .take()
            .and_then(|(_, value)| value);
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
        for event in self.engine.drain_events() {
            match event {
                GroupEvent::MessageReceived {
                    group_id,
                    message_id,
                    sender,
                    epoch,
                    payload,
                    ..
                } if group_id == self.group && Some(&message_id) == content_id.as_ref() => {
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
                        MARMOT_APP_EVENT_KIND_CHAT | MARMOT_APP_EVENT_KIND_REACTION
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
                // Conservatively refuse state changes, reorgs and delayed messages. This
                // slice does not authenticate a prior wire using the current wire's record.
                _ => return Err(ReceiverHold::ChangedState),
            }
        }
        self.record(serde_json::json!({"schema":"receiver-outcome.v1", "sequence":self.sequence,
            "message_id":hex::encode(wire.id.as_slice()), "outcome":outcome, "candidate":candidate}))?;
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

#[path = "protected_semantic.rs"]
mod semantic;
