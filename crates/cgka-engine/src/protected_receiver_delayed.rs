//! Private native peel bindings and non-authoritative delayed presentation.
//! No serialized value can install a capture or mint approval evidence.
use super::*;
use crate::protected_recovery::Journal;
use std::collections::BTreeSet;

pub(crate) const MAX_CAPTURES: usize = crate::message_processor::MAX_DEFERRED_ROWS_PER_SWEEP * 16;
const MAX_ADMITTED: usize = crate::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP;

pub(crate) struct Binding {
    pub(crate) wire_source: u64,
    pub(crate) outcome_source: u64,
    pub(crate) original: RetainedWire,
}
pub(crate) struct Capture {
    pub(crate) group: GroupId,
    pub(crate) admitted: Vec<Binding>,
    pub(crate) peeled: Vec<(MessageId, MessageId)>,
}
impl Capture {
    pub(crate) fn capture(
        &mut self,
        group: &GroupId,
        outer: &MessageId,
        content: &MessageId,
    ) -> Result<(), EngineError> {
        if group != &self.group
            || !self.admitted.iter().any(|b| &b.original.wire.id == outer)
            || self.peeled.iter().any(|(a, b)| a == outer && b != content)
            || self.peeled.len() >= MAX_CAPTURES
        {
            return Err(EngineError::Other(
                "receiver delayed binding refused".into(),
            ));
        }
        self.peeled.push((outer.clone(), content.clone()));
        Ok(())
    }
    pub(crate) fn first(&self, content: &MessageId) -> Option<&Binding> {
        let (outer, _) = self.peeled.iter().find(|(_, id)| id == content)?;
        self.admitted.iter().find(|b| &b.original.wire.id == outer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedDelayed {
    pub(crate) schema: String,
    pub(crate) original_wire_source: u64,
    pub(crate) original_outcome_source: u64,
    pub(crate) original_wire_sha256: String,
    pub(crate) outer_message_id: String,
    pub(crate) content_id: MessageId,
    pub(crate) projection: PendingApplicationProjection,
    pub(crate) candidate: Option<RetainedCandidate>,
}
fn hash_wire(wire: &TransportMessage) -> Result<String, ReceiverHold> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(wire).map_err(|_| ReceiverHold::Malformed)?,
    )))
}
pub(crate) fn validate(
    journal: &Journal,
    value: &serde_json::Value,
    position: u64,
    group: &GroupId,
) -> Result<RetainedDelayed, ReceiverHold> {
    let r: RetainedDelayed =
        serde_json::from_value(value.clone()).map_err(|_| ReceiverHold::Malformed)?;
    if r.schema != "receiver-delayed-outcome.v1"
        || r.original_wire_source.checked_add(1) != Some(r.original_outcome_source)
        || r.original_outcome_source >= position
    {
        return Err(ReceiverHold::ChangedState);
    }
    let w = journal
        .source_at(r.original_wire_source)
        .map_err(|_| ReceiverHold::Journal)?;
    let o = journal
        .source_at(r.original_outcome_source)
        .map_err(|_| ReceiverHold::Journal)?;
    let wire: RetainedWire =
        serde_json::from_value(w.body["value"].clone()).map_err(|_| ReceiverHold::Malformed)?;
    let outcome: RetainedOutcome =
        serde_json::from_value(o.body["value"].clone()).map_err(|_| ReceiverHold::Malformed)?;
    if wire.schema != "receiver-wire.v1"
        || outcome.schema != "receiver-outcome.v1"
        || outcome.sequence != wire.sequence
        || outcome.message_id != r.outer_message_id
        || r.outer_message_id != hex::encode(wire.wire.id.as_slice())
        || r.original_wire_sha256 != hash_wire(&wire.wire)?
        || !outcome.is_opaque_deferred_for(group)
        || r.projection.group != *group
        || !r.projection.matches_id(&r.content_id)
        || r.candidate
            .as_ref()
            .is_some_and(|c| !c.matches_retained(&wire, std::slice::from_ref(&r.projection)))
    {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(r)
}
/// Native work admission retains only bounded IDs, never lifetime history.
pub(crate) fn admit(
    journal: &Journal,
    group: &GroupId,
    ids: &[MessageId],
) -> Result<Capture, ReceiverHold> {
    if ids.len() > MAX_ADMITTED {
        return Err(ReceiverHold::Capacity);
    }
    let mut cursor = journal.source_cursor().map_err(|_| ReceiverHold::Journal)?;
    let mut wire: Option<(u64, RetainedWire)> = None;
    let mut admitted = Vec::new();
    while let Some(record) = cursor.next().map_err(|_| ReceiverHold::Journal)? {
        let v = &record.body["value"];
        if v["schema"] == "receiver-wire.v1" {
            let w: RetainedWire =
                serde_json::from_value(v.clone()).map_err(|_| ReceiverHold::Malformed)?;
            if wire.is_some() {
                return Err(ReceiverHold::ChangedState);
            }
            wire = Some((record.sequence, w));
        } else if v["schema"] == "receiver-outcome.v1" {
            let (source, w) = wire.take().ok_or(ReceiverHold::ChangedState)?;
            let o: RetainedOutcome =
                serde_json::from_value(v.clone()).map_err(|_| ReceiverHold::Malformed)?;
            if o.sequence != w.sequence || o.message_id != hex::encode(w.wire.id.as_slice()) {
                return Err(ReceiverHold::ChangedState);
            }
            if ids.contains(&w.wire.id)
                && o.is_opaque_deferred_for(group)
                && !admitted
                    .iter()
                    .any(|b: &Binding| b.original.wire.id == w.wire.id)
            {
                admitted.push(Binding {
                    wire_source: source,
                    outcome_source: record.sequence,
                    original: w,
                });
            }
        } else if v["schema"] == "receiver-delayed-outcome.v1" && wire.is_some() {
            return Err(ReceiverHold::ChangedState);
        }
    }
    if wire.is_some()
        || ids
            .iter()
            .any(|id| !admitted.iter().any(|b| &b.original.wire.id == id))
    {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(Capture {
        group: group.clone(),
        admitted,
        peeled: Vec::new(),
    })
}
/// Validate the complete native event/pending set without draining either.
pub(crate) fn projections<S: StorageProvider + 'static>(
    receiver: &ProtectedReceiver<S>,
    capture: &Capture,
) -> Result<Vec<serde_json::Value>, ReceiverHold> {
    let pending = receiver
        .engine
        .storage
        .list_pending_application_events()
        .map_err(|_| ReceiverHold::Engine)?;
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for event in &receiver.engine.events_buf {
        if matches!(event,GroupEvent::EpochChanged {group_id,..} if group_id==&receiver.group) {
            continue;
        }
        let GroupEvent::MessageReceived {
            group_id,
            message_id,
            sender,
            epoch,
            payload,
            ..
        } = event
        else {
            return Err(ReceiverHold::ChangedState);
        };
        let projection =
            PendingApplicationProjection::capture(event).ok_or(ReceiverHold::ChangedState)?;
        let binding = capture
            .first(message_id)
            .ok_or(ReceiverHold::ChangedState)?;
        if group_id != &receiver.group
            || !seen.insert(hex::encode(message_id.as_slice()))
            || pending
                .iter()
                .filter(|e| PendingApplicationProjection::capture(e).as_ref() == Some(&projection))
                .count()
                != 1
        {
            return Err(ReceiverHold::ChangedState);
        }
        let app = MarmotAppEvent::decode(payload).map_err(|_| ReceiverHold::Malformed)?;
        app.validate_sender(&hex::encode(sender.as_slice()))
            .map_err(|_| ReceiverHold::Malformed)?;
        let candidate = if sender != &receiver.engine.self_id()
            && receiver.operators.contains(sender)
            && matches!(
                app.kind,
                MARMOT_APP_EVENT_KIND_CHAT
                    | MARMOT_APP_EVENT_KIND_REACTION
                    | MARMOT_APP_EVENT_KIND_DELETE
                    | MARMOT_APP_EVENT_KIND_EDIT
                    | MARMOT_APP_EVENT_KIND_REMOVE
            ) {
            Some(AuthenticatedCandidate {
                sequence: binding.original.sequence,
                received_at_unix_ms: binding.original.received_at_unix_ms,
                group: group_id.clone(),
                message_id: hex::encode(message_id.as_slice()),
                source_epoch: epoch.0,
                sender: sender.clone(),
                application: app,
            })
        } else {
            None
        };
        records.push(serde_json::json!({"schema":"receiver-delayed-outcome.v1", "original_wire_source":binding.wire_source, "original_outcome_source":binding.outcome_source, "original_wire_sha256":hash_wire(&binding.original.wire)?, "outer_message_id":hex::encode(binding.original.wire.id.as_slice()),"content_id":message_id,"projection":projection,"candidate":candidate}));
    }
    if pending.len() != records.len() {
        return Err(ReceiverHold::ChangedState);
    }
    // A peel without an event is benign only with durable terminal duplicate or
    // own-echo state. No cross-interval pending native identity is forgotten.
    for (_, id) in &capture.peeled {
        if seen.contains(&hex::encode(id.as_slice())) {
            continue;
        }
        let native = receiver
            .engine
            .storage
            .get_message(id)
            .map_err(|_| ReceiverHold::Engine)?;
        // A native stored commit/proposal is durable convergence input, not
        // pending application plaintext. Its exact native content identity and
        // wire remain retained; no ACK, discard or presentation is performed.
        let non_application = crate::openmls_projection::decode_openmls_wire_projection(
            &native.payload,
        )
        .is_some_and(|(_, projection)| {
            projection.kind != crate::openmls_projection::OpenMlsContentKind::Application
        });
        if native.group_id != receiver.group
            || (!non_application
                && !matches!(
                    native.state,
                    cgka_traits::message::MessageState::Processed
                        | cgka_traits::message::MessageState::Sent
                ))
        {
            return Err(ReceiverHold::ChangedState);
        }
    }
    Ok(records)
}

/// Non-authoritative native policy-preserving epoch transition, distinct from
/// direct-merge evidence. Only the trusted maintenance owner emits this proof.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedNativeUpdate {
    schema: String,
    group: GroupId,
    pub(crate) before: crate::protected_merge::Projection,
    pub(crate) after: crate::protected_merge::Projection,
    epoch_events: Vec<(u64, u64)>,
}
pub(crate) fn validate_native_update(
    value: &serde_json::Value,
    group: &GroupId,
) -> Result<RetainedNativeUpdate, ReceiverHold> {
    let r: RetainedNativeUpdate =
        serde_json::from_value(value.clone()).map_err(|_| ReceiverHold::Malformed)?;
    if r.schema != "receiver-maintenance-native-update.v1"
        || &r.group != group
        || !r.before.same_policy(&r.after)
        || r.before.epoch >= r.after.epoch
        || r.epoch_events.is_empty()
        || r.epoch_events.len() > MAX_CAPTURES
    {
        return Err(ReceiverHold::ChangedState);
    }
    let mut epoch = r.before.epoch;
    for &(from, to) in &r.epoch_events {
        if from != epoch || to <= from || to > r.after.epoch {
            return Err(ReceiverHold::ChangedState);
        }
        epoch = to;
    }
    if epoch != r.after.epoch {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(r)
}
