//! Private clean native continuation from the exclusively owned anchored source.
//! DTOs below are readback only, never accepted as an external evidence import.
use super::*;
use crate::protected_recovery::Journal;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    epoch: u64,
    indexed_credentials: Vec<(u32, Vec<u8>)>,
    extensions: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Join {
    original_wire: TransportMessage,
    original_wire_sha256: String,
    group: GroupId,
    canonical_content: MessageId,
    authenticated_welcomer: MemberId,
    joined: Projection,
}
impl Join {
    fn matches(&self, event: &GroupEvent) -> bool {
        matches!(event,GroupEvent::GroupJoined {group_id,via_welcome,explicitly_confirmed:false,welcomer:Some(sender)}
            if group_id==&self.group && via_welcome==&self.original_wire.id && sender==&self.authenticated_welcomer)
    }
}
fn decode<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> Result<T, ReceiverHold> {
    serde_json::from_value(value.clone()).map_err(|_| ReceiverHold::ChangedState)
}
fn sha(value: &impl Serialize) -> Result<String, ReceiverHold> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| ReceiverHold::Malformed)?,
    )))
}
impl<S: StorageProvider + 'static> ProtectedReceiver<S> {
    /// Source-owned descriptors and enrolled Engine only. This verifies native
    /// history but deliberately leaves pending plaintext intact until semantic
    /// catalog/profile reconstruction has also succeeded.
    pub(super) fn reopen_ordered(
        mut engine: Engine<S>,
        group: GroupId,
        operators: Vec<MemberId>,
        journal: Journal,
    ) -> Result<Self, ReceiverHold> {
        engine
            .hydrate_all_stored_groups()
            .map_err(|_| ReceiverHold::ChangedState)?;
        let enrollment = journal.enrollment().map_err(|_| ReceiverHold::Journal)?;
        let mut operator_hex: Vec<_> = operators
            .iter()
            .map(|m| hex::encode(m.as_slice()))
            .collect();
        operator_hex.sort();
        if operators.is_empty()
            || operators.contains(&engine.self_id())
            || operators.len() > 64
            || operator_hex.windows(2).any(|p| p[0] == p[1])
            || enrollment.account != hex::encode(engine.self_id().as_slice())
            || enrollment.group != hex::encode(group.as_slice())
            || enrollment.operators != operator_hex
            || engine
                .storage
                .list_groups()
                .map_err(|_| ReceiverHold::Engine)?
                != vec![group.clone()]
        {
            return Err(ReceiverHold::ChangedState);
        }
        let template = crate::protected_capability_policy::Template::from_policy(
            &enrollment.capability_template,
            &enrollment.capability_policy_sha256,
        )
        .map_err(|_| ReceiverHold::Configuration)?;
        engine
            .with_mls_group(&group, |native| template.validate_group(native))
            .map_err(|_| ReceiverHold::ChangedState)?;
        let mut cursor = journal.source_cursor().map_err(|_| ReceiverHold::Journal)?;
        cursor
            .next()
            .map_err(|_| ReceiverHold::Journal)?
            .ok_or(ReceiverHold::ChangedState)?;
        let original = cursor
            .next()
            .map_err(|_| ReceiverHold::Journal)?
            .ok_or(ReceiverHold::ChangedState)?;
        if original.sequence != 2 || original.body["value"]["schema"] != "receiver-enrollment.v1" {
            return Err(ReceiverHold::ChangedState);
        }
        let join: Join = decode(&original.body["value"]["native_join"])?;
        if join.group != group
            || sha(&join)? != enrollment.welcome_provenance_sha256
            || sha(&join.original_wire)? != join.original_wire_sha256
            || sha(&join.joined)? != enrollment.initial_native_state_sha256
        {
            return Err(ReceiverHold::ChangedState);
        }
        let mut native = serde_json::to_value(&join.joined).map_err(|_| ReceiverHold::Malformed)?;
        let mut sequence = 0;
        while let Some(record) = cursor.next().map_err(|_| ReceiverHold::Journal)? {
            let value = &record.body["value"];
            if value["schema"] != "receiver-outcome.v1" {
                continue;
            }
            sequence = value["sequence"]
                .as_u64()
                .ok_or(ReceiverHold::ChangedState)?;
            let merge = &value["native_merge"];
            if merge.is_null() {
                continue;
            }
            let before = &merge["before"];
            let after = &merge["after"];
            let old: Projection = decode(before)?;
            let new: Projection = decode(after)?;
            let merge_group: GroupId = decode(&merge["group"])?;
            let leaf = merge["committer_leaf"]
                .as_u64()
                .ok_or(ReceiverHold::ChangedState)?;
            let proposals: Vec<String> = decode(&merge["proposals"])?;
            if before != &native
                || merge_group != group
                || old.epoch.checked_add(1) != Some(new.epoch)
                || old.indexed_credentials != new.indexed_credentials
                || old.extensions != new.extensions
                || !old
                    .indexed_credentials
                    .iter()
                    .any(|(index, _)| u64::from(*index) == leaf)
                || proposals.iter().any(|p| p != "update")
            {
                return Err(ReceiverHold::ChangedState);
            }
            native = after.clone();
        }
        let current = engine
            .with_mls_group(&group, |actual| {
                if !engine.receiver_group_quiet(&group, actual)? {
                    return Err(EngineError::Other("receiver reopen not quiet".into()));
                }
                crate::protected_merge::Projection::read(actual)
            })
            .map_err(|_| ReceiverHold::ChangedState)?;
        if serde_json::to_value(current).map_err(|_| ReceiverHold::Malformed)? != native {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(Self {
            engine,
            group,
            operators,
            journal: ReceiverJournal::Ordered(journal),
            sequence,
            latched: false,
        })
    }
    /// Validate all actual pending native data before semantic reconstruction
    /// can append any decision, conflict or expiry. This performs no deletion.
    /// A retained original Welcome is accepted only through its exact capture.
    pub(super) fn check_reopened_pending(&self) -> Result<Vec<MessageId>, ReceiverHold> {
        let ReceiverJournal::Ordered(journal) = &self.journal else {
            return Err(ReceiverHold::Configuration);
        };
        let join: Join = decode(
            &journal
                .source_at(2)
                .map_err(|_| ReceiverHold::Journal)?
                .body["value"]["native_join"],
        )?;
        let pending = self
            .engine
            .storage
            .list_pending_application_events()
            .map_err(|_| ReceiverHold::Journal)?;
        let mut projections = Vec::new();
        let mut ids = Vec::new();
        for event in &pending {
            if join.matches(event) {
                ids.push(join.original_wire.id.clone());
                continue;
            }
            let projection =
                PendingApplicationProjection::capture(event).ok_or(ReceiverHold::ChangedState)?;
            if let GroupEvent::MessageReceived { message_id, .. } = event {
                ids.push(message_id.clone())
            }
            projections.push(projection);
        }
        journal
            .verify_pending(&projections)
            .map_err(|_| ReceiverHold::ChangedState)?;
        for event in &self.engine.events_buf {
            if join.matches(event) && pending.iter().any(|p| join.matches(p)) {
                continue;
            }
            let actual =
                PendingApplicationProjection::capture(event).ok_or(ReceiverHold::ChangedState)?;
            if !projections.contains(&actual) {
                return Err(ReceiverHold::ChangedState);
            }
        }
        Ok(ids)
    }
    /// The exclusive owner calls this only after the precheck and successful
    /// semantic projection; no native ingress runs between these two steps.
    pub(super) fn acknowledge_reopened_pending(
        &mut self,
        ids: &[MessageId],
    ) -> Result<(), ReceiverHold> {
        self.engine
            .storage
            .delete_pending_application_events(ids)
            .map_err(|_| ReceiverHold::Journal)?;
        self.engine.events_buf.clear(); // Every entry positively matched above.
        Ok(())
    }
}
