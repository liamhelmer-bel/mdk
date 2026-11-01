//! Actual direct native merge evidence; never inferred from public epoch events.
use cgka_traits::{
    EngineError,
    types::{GroupId, MemberId, MessageId},
};
use openmls::group::MlsGroup;
use serde::Serialize;
use tls_codec::Serialize as _;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Projection {
    epoch: u64,
    indexed_credentials: Vec<(u32, Vec<u8>)>,
    extensions: Vec<u8>,
}
impl Projection {
    pub(crate) fn same_policy(&self, other: &Self) -> bool {
        self.indexed_credentials == other.indexed_credentials && self.extensions == other.extensions
    }
    pub(crate) fn read(group: &MlsGroup) -> Result<Self, EngineError> {
        let mut indexed_credentials = group
            .members()
            .map(|member| {
                Ok((
                    member.index.u32(),
                    member.credential.tls_serialize_detached().map_err(|e| {
                        EngineError::Serialize(format!("receiver credential: {e:?}"))
                    })?,
                ))
            })
            .collect::<Result<Vec<_>, EngineError>>()?;
        indexed_credentials.sort_by_key(|(index, _)| *index);
        Ok(Self {
            epoch: group.epoch().as_u64(),
            indexed_credentials,
            extensions: group
                .extensions()
                .tls_serialize_detached()
                .map_err(|e| EngineError::Serialize(format!("receiver extensions: {e:?}")))?,
        })
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct DirectMerge {
    group: GroupId,
    canonical_content: MessageId,
    committer: MemberId,
    committer_leaf: u32,
    before: Projection,
    after: Projection,
    proposals: Vec<String>,
}
impl DirectMerge {
    pub(crate) fn new(
        group: GroupId,
        canonical_content: MessageId,
        committer: MemberId,
        committer_leaf: u32,
        before: Projection,
        after: Projection,
        proposals: Vec<String>,
    ) -> Self {
        Self {
            group,
            canonical_content,
            committer,
            committer_leaf,
            before,
            after,
            proposals,
        }
    }
    /// Necessary native evidence only. Owning recovery must additionally verify current
    /// native stability, no pending/automatic outputs, exact enrollment and journal it.
    pub(crate) fn unchanged_policy_update(&self) -> bool {
        self.before.epoch.checked_add(1) == Some(self.after.epoch)
            && self.before.indexed_credentials == self.after.indexed_credentials
            && self.before.extensions == self.after.extensions
            && self.proposals.iter().all(|kind| kind == "update")
            && self
                .before
                .indexed_credentials
                .iter()
                .any(|(index, _)| *index == self.committer_leaf)
    }
}
/// Created only by the private native owner around one actual ingest. Capturing a
/// second merge or convergence prevents treating a multi-step pass as a direct update.
#[derive(Default, Debug)]
pub(crate) struct Capture {
    pub(crate) convergence_entered: bool,
    pub(crate) requested_group: Option<GroupId>,
    pub(crate) direct: Option<DirectMerge>,
    pub(crate) template: Option<crate::protected_capability_policy::Template>,
    #[cfg(test)]
    pub(crate) fail_retain: bool,
}
impl Capture {
    pub(crate) fn for_group(group: GroupId) -> Self {
        Self {
            requested_group: Some(group),
            ..Self::default()
        }
    }
    pub(crate) fn invalidate(&mut self) {
        self.convergence_entered = true;
        self.direct = None;
    }
    pub(crate) fn retain(&mut self, evidence: DirectMerge) -> Result<(), EngineError> {
        #[cfg(test)]
        if self.fail_retain {
            return Err(EngineError::Other(
                "injected capture failure after native commit".into(),
            ));
        }
        if self.direct.is_some() {
            return Err(EngineError::Other(
                "receiver observed multiple direct merges".into(),
            ));
        }
        self.direct = Some(evidence);
        Ok(())
    }
    pub(crate) fn matches_epoch(
        &self,
        group: &GroupId,
        before: u64,
        after: u64,
        content: &MessageId,
    ) -> bool {
        self.qualifies(group, content)
            && self
                .direct
                .as_ref()
                .is_some_and(|merge| merge.before.epoch == before && merge.after.epoch == after)
    }
    pub(crate) fn qualifies(&self, group: &GroupId, content: &MessageId) -> bool {
        !self.convergence_entered
            && self.direct.as_ref().is_some_and(|merge| {
                &merge.group == group
                    && &merge.canonical_content == content
                    && merge.unchanged_policy_update()
            })
    }
}

pub(crate) fn validate_staged_update(
    group: &MlsGroup,
    staged: &openmls::group::StagedCommit,
) -> Result<(), EngineError> {
    if staged
        .queued_proposals()
        .any(|queued| !matches!(queued.proposal(), openmls::prelude::Proposal::Update(_)))
        || staged
            .group_context()
            .extensions()
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("receiver staged extensions: {e:?}")))?
            != group.extensions().tls_serialize_detached().map_err(|e| {
                EngineError::Serialize(format!("receiver current extensions: {e:?}"))
            })?
    {
        return Err(EngineError::Other(
            "receiver update changes enrolled policy".into(),
        ));
    }
    Ok(())
}

impl<S: cgka_traits::storage::StorageProvider> crate::Engine<S> {
    /// Reads actual native work state; not an externally supplied readiness verdict.
    pub(crate) fn receiver_direct_update_candidate(
        &self,
        group: &GroupId,
        epoch: cgka_traits::EpochId,
        current: cgka_traits::EpochId,
        native: &MlsGroup,
    ) -> Result<bool, EngineError> {
        Ok(epoch == current
            && self.receiver_merge_capture.as_ref().is_some_and(|capture| {
                capture.requested_group.as_ref() == Some(group)
                    && !capture.convergence_entered
                    && capture.direct.is_none()
            })
            && self.receiver_group_quiet(group, native)?)
    }
    pub(crate) fn receiver_group_quiet(
        &self,
        group: &GroupId,
        native: &MlsGroup,
    ) -> Result<bool, EngineError> {
        Ok(matches!(
            self.epoch_manager.state(group),
            Some(cgka_traits::engine_state::EpochState::Stable { .. })
        ) && !self.quarantined_groups().iter().any(|(id, _)| id == group)
            && self.auto_publish_buf.is_empty()
            && self.auto_proposal_buf.is_empty()
            && self.epoch_manager.pending_refs_for_group(group).is_empty()
            && native.pending_commit().is_none()
            && native.pending_proposals().next().is_none()
            && !self.has_pending_convergence_inputs(group)?
            && !self.has_pending_canonical_applications(group)?
            && !self
                .storage
                .convergence_pass(group)?
                .is_some_and(|pass| pass.is_active()))
    }
}
