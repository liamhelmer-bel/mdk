//! Exact retained artifacts with fsynced attempt/report records. This is not a
//! bootstrap admission factory or a subscription-capable account transport.

use std::fs::File;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use tokio::sync::Mutex as AsyncMutex;
use transport_nostr_adapter::{NostrPublishOutcome, NostrRelayClient, NostrSubscription};
use transport_nostr_peeler::NostrTransportEvent;

use crate::generation::Generation;
use crate::initializer::{Artifact, Ledger};

#[derive(Clone)]
pub(crate) struct JournaledRelay {
    ledger: Arc<Mutex<Ledger>>,
    serial: Arc<AsyncMutex<()>>,
    bytes: [Vec<u8>; 3],
    bindings: Vec<Artifact>,
    relay: Arc<dyn NostrRelayClient>,
    timeout: Duration,
}

fn hold() -> TransportAdapterError {
    TransportAdapterError::Publish(
        "initialization publication unresolved; preserve exact generation".into(),
    )
}

impl JournaledRelay {
    pub(crate) fn new(
        ledger: Ledger,
        generation: &Generation,
        retained: &File,
        relay: Arc<dyn NostrRelayClient>,
        timeout: Duration,
    ) -> Result<Self, TransportAdapterError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(hold());
        }
        let bindings = ledger.publication_bindings().map_err(|_| hold())?;
        // Reads the actual same-generation retained file, authenticates all
        // three Schnorr signatures/account identities and exact ledger hashes.
        let bytes = generation
            .read_publications(retained, &bindings)
            .map_err(|_| hold())?;
        Ok(Self {
            ledger: Arc::new(Mutex::new(ledger)),
            serial: Arc::new(AsyncMutex::new(())),
            bytes,
            bindings,
            relay,
            timeout,
        })
    }

    // Blocking durability runs outside the async runtime worker. Cancellation
    // never cancels an already-issued fsync or turns it into permission to send.
    async fn update<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Ledger) -> Result<T, crate::initializer::Error> + Send + 'static,
    ) -> Result<T, TransportAdapterError> {
        let ledger = self.ledger.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = ledger.lock().map_err(|_| crate::initializer::Error::Hold)?;
            operation(&mut guard)
        })
        .await
        .map_err(|_| hold())?
        .map_err(|_| hold())
    }

    async fn unknown(
        &self,
        sequence: usize,
        failed: Vec<String>,
    ) -> Result<(), TransportAdapterError> {
        self.update(move |ledger| ledger.unknown_attempt(sequence, failed))
            .await
    }

    async fn report(
        &self,
        sequence: usize,
        index: usize,
        outcome: &NostrPublishOutcome,
    ) -> Result<Vec<String>, TransportAdapterError> {
        let accepted = outcome
            .accepted
            .iter()
            .map(|a| a.endpoint.0.clone())
            .collect();
        let failed = outcome
            .failed
            .iter()
            .map(|a| a.endpoint.0.clone())
            .collect();
        self.update(move |ledger| {
            ledger.report_attempt(sequence, accepted, failed)?;
            ledger.accepted(index)
        })
        .await
    }

    // Caller cancellation detaches this bounded task; it retains the serial
    // guard until the actual begin/network/report sequence is durably complete.
    // A retry cannot overtake an in-flight fsync or discard an observed receipt.
    async fn publish_retained(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let _serial = self.serial.lock().await;
        let bytes = serde_json::to_vec(event).map_err(|_| hold())?;
        let index = self
            .bytes
            .iter()
            .position(|b| b == &bytes)
            .ok_or_else(hold)?;
        let binding = &self.bindings[index];
        if required_acks != binding.required_acks
            || !endpoints.iter().map(|e| &e.0).eq(binding.targets.iter())
        {
            return Err(hold());
        }
        let owned_binding = binding.clone();
        let sequence = self
            .update(move |ledger| ledger.begin_attempt(index, &owned_binding))
            .await?;
        // The owned task survives caller cancellation. Its finite network timeout
        // records Unknown before releasing serialization; never replace material.
        match tokio::time::timeout(
            self.timeout,
            // Capture an actual positive report below the overall threshold.
            // The SDK may return after its first positive; the immutable
            // publisher threshold is enforced against the fsynced union.
            // This does not guarantee fairness among slow relay endpoints.
            self.relay.publish_event(endpoints, event, 1),
        )
        .await
        {
            Ok(Ok(outcome)) => {
                if outcome
                    .message_id
                    .as_ref()
                    .is_some_and(|id| hex::encode(id.as_slice()) != binding.event_id)
                {
                    self.unknown(sequence, vec![]).await?;
                    return Err(hold());
                }
                let accepted = match self.report(sequence, index, &outcome).await {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        self.unknown(sequence, vec![]).await?;
                        return Err(hold());
                    }
                };
                let mut cumulative =
                    NostrPublishOutcome::accepted(accepted.iter().cloned().map(TransportEndpoint));
                cumulative.message_id = outcome.message_id;
                cumulative.failed = outcome
                    .failed
                    .into_iter()
                    .filter(|failure| !accepted.contains(&failure.endpoint.0))
                    .collect();
                Ok(cumulative)
            }
            Ok(Err(TransportAdapterError::PublishEndpoints(failure))) => {
                let failed: Vec<_> = failure
                    .endpoint_failures
                    .into_iter()
                    .map(|e| e.endpoint.0)
                    .collect();
                let valid = failure
                    .message_id
                    .as_ref()
                    .is_none_or(|id| hex::encode(id.as_slice()) == binding.event_id)
                    && failed
                        .iter()
                        .enumerate()
                        .all(|(i, e)| binding.targets.contains(e) && !failed[..i].contains(e));
                self.unknown(sequence, if valid { failed } else { vec![] })
                    .await?;
                Err(hold())
            }
            _ => {
                self.unknown(sequence, vec![]).await?;
                Err(hold())
            }
        }
    }

    // Relay receipts alone cannot assert native promotion. Reconcile only an
    // independently opened current SQLCipher lifecycle matching the exact
    // retained package/event. A crash after native promotion but before this
    // append is recoverable by repeating this readback, without another send.
    pub(crate) async fn published(
        &self,
        generation: &Generation,
    ) -> Result<(), TransportAdapterError> {
        let (database, keys, key, retained) =
            generation.retained_native_inputs().map_err(|_| hold())?;
        let bytes = self.bytes[2].clone();
        let endpoints = self.bindings[2]
            .targets
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect();
        let prepared = tokio::task::spawn_blocking(move || {
            let result = crate::preparation::promoted_from_retained(
                &database, &key, &keys, bytes, endpoints,
            );
            drop(retained);
            result
        })
        .await
        .map_err(|_| hold())?
        .map_err(|_| hold())?;
        self.update(move |ledger| {
            if ledger.publication_slot()? != prepared.publication.slot_id {
                return Err(crate::initializer::Error::Hold);
            }
            ledger.published()
        })
        .await
    }
}

#[async_trait]
impl NostrRelayClient for JournaledRelay {
    async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }
    async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }
    async fn unsubscribe_account(&self, _: &MemberId) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let owner = self.clone();
        let endpoints = endpoints.to_vec();
        let event = event.clone();
        tokio::spawn(async move {
            owner
                .publish_retained(&endpoints, &event, required_acks)
                .await
        })
        .await
        .map_err(|_| hold())?
    }
}
