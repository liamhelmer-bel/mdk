//! Bounded native maintenance before conversation readiness or outbound intent.
//! Only effect-free deferred-peel housekeeping is accepted here. Native context
//! evolution, pending plaintext, events, and publication work remain held.
use super::*;

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
    if factory.receiver.mode != crate::protected_receiver::ReceiverMode::ConversationOnly
        || !factory.receiver.conversation_sealed
    {
        return Err(ReceiverHold::Configuration);
    }
    let group = factory.receiver.group.clone();
    let before = factory
        .receiver
        .engine
        .group_authority(&group)
        .map_err(|_| ReceiverHold::ChangedState)?;
    if before.lifecycle != cgka_traits::GroupLifecycleState::Stable || !quiet(factory)? {
        factory.held = true;
        return Err(ReceiverHold::ChangedState);
    }
    let context = factory
        .receiver
        .engine
        .with_mls_group(&group, |native| {
            Ok(native.epoch_authenticator().as_slice().to_vec())
        })
        .map_err(|_| ReceiverHold::ChangedState)?;
    // Persist uncertainty before the first native mutation. An interrupted
    // quantum cannot be resumed by reopening its conversation delivery history.
    history.append(store::Record::ConvergenceStarted)?;
    factory.held = true;
    let mut settled = false;
    for _ in 0..QUANTA {
        settled = factory
            .receiver
            .engine
            .advance_convergence_inputs(&group)
            .await
            .map_err(|_| {
                stage("native-convergence-refused");
                ReceiverHold::Latched
            })?;
        let after = factory
            .receiver
            .engine
            .group_authority(&group)
            .map_err(|_| ReceiverHold::ChangedState)?;
        let same_context = factory
            .receiver
            .engine
            .with_mls_group(&group, |native| {
                Ok(native.epoch_authenticator().as_slice() == context)
            })
            .map_err(|_| ReceiverHold::ChangedState)?;
        if before != after || !same_context || !quiet(factory)? {
            stage("native-convergence-unexpected-effects");
            return Err(ReceiverHold::ChangedState);
        }
        if settled {
            break;
        }
    }
    if settled {
        let native_quiet = factory
            .receiver
            .engine
            .with_mls_group(&group, |native| {
                factory.receiver.engine.receiver_group_quiet(&group, native)
            })
            .map_err(|_| ReceiverHold::ChangedState)?;
        if !native_quiet {
            stage("native-convergence-not-quiet");
            return Err(ReceiverHold::ChangedState);
        }
    }
    history.append(store::Record::ConvergenceFinished { settled })?;
    factory.held = false;
    Ok(settled)
}
