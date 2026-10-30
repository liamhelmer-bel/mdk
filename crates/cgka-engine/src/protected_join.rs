//! Native enrollment evidence captured only at the authenticated join commit seam.
//! No historical reconstruction, public opener or production custody is supplied.
use crate::{Engine, protected_merge::Projection};
use cgka_traits::{
    EngineError,
    engine::{CgkaEngine, GroupEvent},
    storage::StorageProvider,
    transport::TransportMessage,
    types::{GroupId, MemberId, MessageId},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write};

#[derive(Debug, Serialize)]
pub(crate) struct JoinEvidence {
    pub(crate) original_wire: TransportMessage,
    original_wire_sha256: String,
    pub(crate) group: GroupId,
    canonical_content: MessageId,
    authenticated_welcomer: MemberId,
    pub(crate) joined: Projection,
}
impl JoinEvidence {
    pub(crate) fn digest(&self) -> Result<String, EngineError> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|e| EngineError::Serialize(e.to_string()))?,
        )))
    }
    pub(crate) fn matches_pending(&self, event: &GroupEvent) -> bool {
        matches!(event, GroupEvent::GroupJoined { group_id, via_welcome, explicitly_confirmed: false, welcomer: Some(welcomer) }
            if group_id == &self.group && via_welcome == &self.original_wire.id && welcomer == &self.authenticated_welcomer)
    }
}
pub(crate) struct Capture {
    wire: TransportMessage,
    wire_sha256: String,
    evidence: Option<JoinEvidence>,
    failed: bool,
}
impl Capture {
    pub(crate) fn invalidate(&mut self) {
        self.failed = true;
        self.evidence = None;
    }
    pub(crate) fn committed(
        &mut self,
        group: GroupId,
        outer: &MessageId,
        content: MessageId,
        welcomer: MemberId,
        joined: Projection,
    ) -> Result<(), EngineError> {
        if self.failed || outer != &self.wire.id || self.evidence.is_some() {
            return Err(EngineError::Other("receiver join capture changed".into()));
        }
        self.evidence = Some(JoinEvidence {
            original_wire: self.wire.clone(),
            original_wire_sha256: self.wire_sha256.clone(),
            group,
            canonical_content: content,
            authenticated_welcomer: welcomer,
            joined,
        });
        Ok(())
    }
}

/// Private descriptor handoff only. The eventual protected opener must establish
/// O_EXCL/nofollow/parent custody; these descriptor checks do not establish it.
pub(super) struct JoinIntent {
    pub(super) file: File,
    pub(super) directory: File,
}

impl<S: StorageProvider + 'static> Engine<S> {
    /// Fresh native join only: positively retain original wire before consuming
    /// the KeyPackage. Any later failure keeps the intent and never retries it.
    pub(super) async fn receiver_join_owned(
        &mut self,
        wire: TransportMessage,
        mut intent: JoinIntent,
    ) -> Result<JoinEvidence, EngineError> {
        use std::os::unix::fs::MetadataExt;
        let fail = || EngineError::Other("receiver enrollment held".into());
        let metadata = intent.file.metadata().map_err(|_| fail())?;
        if !metadata.is_file()
            || metadata.len() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || !intent.directory.metadata().map_err(|_| fail())?.is_dir()
            || self.receiver_join_capture.is_some()
            || !self.storage.list_groups()?.is_empty()
            || !self.storage.list_pending_application_events()?.is_empty()
            || !self.events_buf.is_empty()
            || !self.auto_publish_buf.is_empty()
            || !self.auto_proposal_buf.is_empty()
        {
            return Err(fail());
        }
        intent.file.try_lock().map_err(|_| fail())?;
        let bytes = serde_json::to_vec(&wire).map_err(|e| EngineError::Serialize(e.to_string()))?;
        if bytes.len() > 1024 * 1024 {
            return Err(fail());
        }
        intent
            .file
            .write_all(&bytes)
            .and_then(|_| intent.file.sync_all())
            .and_then(|_| intent.directory.sync_all())
            .map_err(|_| fail())?;
        self.receiver_join_capture = Some(Capture {
            wire: wire.clone(),
            wire_sha256: hex::encode(Sha256::digest(bytes)),
            evidence: None,
            failed: false,
        });
        let result = self.join_welcome(wire).await;
        let captured = self.receiver_join_capture.take().ok_or_else(fail)?;
        let group = result?;
        if captured.failed {
            return Err(fail());
        }
        let evidence = captured.evidence.ok_or_else(fail)?;
        let current = self.with_mls_group(&group, |native| {
            if !self.receiver_group_quiet(&group, native)? {
                return Err(fail());
            }
            Projection::read(native)
        })?;
        let pending = self.storage.list_pending_application_events()?;
        if evidence.group != group
            || evidence.joined != current
            || pending.len() != 1
            || !evidence.matches_pending(&pending[0])
            || self.events_buf.len() != 1
            || !evidence.matches_pending(&self.events_buf[0])
        {
            return Err(fail());
        }
        // No acknowledgment here. The owner must first bind this original live
        // evidence into its durable protected header + independent anchor.
        Ok(evidence)
    }
}

#[cfg(test)]
#[path = "protected_join_tests.rs"]
pub(crate) mod tests;
