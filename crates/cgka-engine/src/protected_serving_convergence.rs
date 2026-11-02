//! Bounded native maintenance with exact retained-wire conversation projection.
use super::*;
use crate::protected_receiver::delayed;

fn quiet<S: StorageProvider + 'static>(factory: &SemanticFactory<S>) -> Result<bool, ReceiverHold> {
    let engine = &factory.receiver.engine;
    Ok(engine.events_buf.is_empty()
        && engine.auto_publish_buf.is_empty()
        && engine.auto_proposal_buf.is_empty()
        && engine
            .storage
            .list_pending_application_events()
            .map_err(|_| ReceiverHold::Engine)?
            .is_empty()
        && !engine
            .has_pending_canonical_applications(&factory.receiver.group)
            .map_err(|_| ReceiverHold::Engine)?)
}
/// Readiness probes never drive native state or write maintenance receipts.
pub(super) fn settled<S: StorageProvider + 'static>(
    factory: &mut SemanticFactory<S>,
) -> Result<bool, ReceiverHold> {
    let group = factory.receiver.group.clone();
    if factory
        .receiver
        .engine
        .receiver_deferred_work_due(&group)
        .map_err(|_| ReceiverHold::Engine)?
    {
        return Ok(false);
    }
    let engine = &factory.receiver.engine;
    let group = &group;
    if engine
        .group_authority(group)
        .map_err(|_| ReceiverHold::Engine)?
        .lifecycle
        != cgka_traits::GroupLifecycleState::Stable
        || !quiet(factory)?
        || engine
            .has_pending_convergence_inputs(group)
            .map_err(|_| ReceiverHold::Engine)?
    {
        return Ok(false);
    }
    engine
        .with_mls_group(group, |native| engine.receiver_group_quiet(group, native))
        .map_err(|_| ReceiverHold::Engine)
}
/// Owner-driven work treats only an effect-free refusal as retryable.
pub(super) async fn maintain<S: StorageProvider + 'static>(
    factory: &mut SemanticFactory<S>,
    history: &mut store::Store,
) -> Result<(), ReceiverHold> {
    match ready(factory, history).await {
        Ok(_) => Ok(()),
        Err(ReceiverHold::Engine | ReceiverHold::Capacity)
            if !factory.held && !factory.receiver.latched =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}
pub(super) async fn ready<S: StorageProvider + 'static>(
    factory: &mut SemanticFactory<S>,
    history: &mut store::Store,
) -> Result<bool, ReceiverHold> {
    bounded::<S, 16>(factory, history).await
}
pub(super) async fn bounded<S: StorageProvider + 'static, const QUANTA: usize>(
    factory: &mut SemanticFactory<S>,
    history: &mut store::Store,
) -> Result<bool, ReceiverHold> {
    if factory.held || factory.receiver.latched {
        return Err(ReceiverHold::Latched);
    }
    if QUANTA > 16
        || factory.receiver.mode != crate::protected_receiver::ReceiverMode::ConversationOnly
        || !factory.receiver.conversation_sealed
    {
        return Err(ReceiverHold::Configuration);
    }
    let group = factory.receiver.group.clone();
    let before = factory
        .receiver
        .engine
        .group_authority(&group)
        .map_err(|_| ReceiverHold::Engine)?;
    if before.lifecycle != cgka_traits::GroupLifecycleState::Stable || !quiet(factory)? {
        return Err(ReceiverHold::Engine);
    }
    if settled(factory)? {
        return Ok(true);
    }
    let ids: Vec<_> = factory
        .receiver
        .engine
        .storage
        .list_deferred_message_metadata(&group)
        .map_err(|_| ReceiverHold::Engine)?
        .into_iter()
        .map(|m| m.id)
        .collect();
    let capture = delayed::admit(factory.ordered()?, &group, &ids)?;
    let context = factory
        .receiver
        .engine
        .with_mls_group(&group, |native| {
            Ok(native.epoch_authenticator().as_slice().to_vec())
        })
        .map_err(|_| ReceiverHold::Engine)?;
    // After this durable boundary every uncertainty remains held on reopen.
    history.append(store::Record::ConvergenceStarted)?;
    factory.held = true;
    factory.receiver.engine.receiver_delayed_capture = Some(capture);
    let result = advance::<S, QUANTA>(factory, history, &group, before, &context).await;
    factory.receiver.engine.receiver_delayed_capture = None;
    result
}
async fn advance<S: StorageProvider + 'static, const QUANTA: usize>(
    factory: &mut SemanticFactory<S>,
    history: &mut store::Store,
    group: &cgka_traits::types::GroupId,
    before: crate::group_authority::GroupAuthoritySnapshot,
    context: &[u8],
) -> Result<bool, ReceiverHold> {
    let mut settled = false;
    for _ in 0..QUANTA {
        settled = factory
            .receiver
            .engine
            .advance_convergence_inputs(group)
            .await
            .map_err(|_| {
                stage("native-convergence-refused");
                ReceiverHold::Latched
            })?;
        let engine = &factory.receiver.engine;
        let after = engine
            .group_authority(group)
            .map_err(|_| ReceiverHold::ChangedState)?;
        let same = engine
            .with_mls_group(group, |native| {
                Ok(native.epoch_authenticator().as_slice() == context)
            })
            .map_err(|_| ReceiverHold::ChangedState)?;
        if before != after
            || !same
            || !engine.auto_publish_buf.is_empty()
            || !engine.auto_proposal_buf.is_empty()
        {
            stage("native-convergence-unexpected-effects");
            return Err(ReceiverHold::ChangedState);
        }
        if settled {
            break;
        }
    }
    let capture = factory
        .receiver
        .engine
        .receiver_delayed_capture
        .as_ref()
        .ok_or(ReceiverHold::ChangedState)?;
    let records = delayed::projections(&factory.receiver, capture).inspect_err(|_| {
        stage("native-convergence-retained-binding");
    })?;
    let mut ids = Vec::new();
    for record in records {
        let projection: delayed::RetainedDelayed =
            serde_json::from_value(record.clone()).map_err(|_| ReceiverHold::Malformed)?;
        ids.push(projection.content_id);
        factory.receiver.record(record)?;
    }
    // Rebuild/advance the same validated catalog before plaintext acknowledgment.
    factory.sync_catalog()?;
    factory.held = true;
    let pending = factory
        .receiver
        .engine
        .storage
        .list_pending_application_events()
        .map_err(|_| ReceiverHold::Journal)?;
    let projections: Vec<_> = pending
        .iter()
        .map(crate::protected_receiver::PendingApplicationProjection::capture)
        .collect::<Option<_>>()
        .ok_or(ReceiverHold::ChangedState)?;
    factory
        .ordered()?
        .verify_pending(&projections, Some(group))
        .map_err(|_| ReceiverHold::ChangedState)?;
    factory
        .receiver
        .engine
        .storage
        .delete_pending_application_events(&ids)
        .map_err(|_| ReceiverHold::Journal)?;
    // Only the fully validated, anchored set is drained. No drain-and-ignore.
    let drained = factory.receiver.engine.drain_events();
    if drained.len() != ids.len() {
        return Err(ReceiverHold::ChangedState);
    }
    if !quiet(factory)? {
        stage("native-convergence-not-quiet");
        return Err(ReceiverHold::ChangedState);
    }
    if settled
        && !factory
            .receiver
            .engine
            .with_mls_group(group, |native| {
                factory.receiver.engine.receiver_group_quiet(group, native)
            })
            .map_err(|_| ReceiverHold::ChangedState)?
    {
        return Err(ReceiverHold::ChangedState);
    }
    history.append(store::Record::ConvergenceFinished { settled })?;
    factory.held = false;
    Ok(settled)
}
