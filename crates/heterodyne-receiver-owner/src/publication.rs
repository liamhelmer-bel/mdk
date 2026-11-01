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

pub(crate) struct JournaledRelay {
    ledger: Mutex<Ledger>,
    serial: AsyncMutex<()>,
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
            ledger: Mutex::new(ledger),
            serial: AsyncMutex::new(()),
            bytes,
            bindings,
            relay,
            timeout,
        })
    }

    fn unknown(&self, sequence: usize, failed: Vec<String>) -> Result<(), TransportAdapterError> {
        self.ledger
            .lock()
            .map_err(|_| hold())?
            .unknown_attempt(sequence, failed)
            .map_err(|_| hold())
    }

    fn report(
        &self,
        sequence: usize,
        outcome: &NostrPublishOutcome,
    ) -> Result<(), TransportAdapterError> {
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
        self.ledger
            .lock()
            .map_err(|_| hold())?
            .report_attempt(sequence, accepted, failed)
            .map_err(|_| hold())
    }

    pub(crate) fn published(&self) -> Result<(), TransportAdapterError> {
        self.ledger
            .lock()
            .map_err(|_| hold())?
            .published()
            .map_err(|_| hold())
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
        let sequence = self
            .ledger
            .lock()
            .map_err(|_| hold())?
            .begin_attempt(index, binding)
            .map_err(|_| hold())?;
        // Cancellation of this future leaves a durable Begun marker. A timeout
        // or error also remains possibly exposed; no replacement is prepared.
        match tokio::time::timeout(
            self.timeout,
            self.relay.publish_event(endpoints, event, required_acks),
        )
        .await
        {
            Ok(Ok(outcome)) => {
                if outcome
                    .message_id
                    .as_ref()
                    .is_some_and(|id| hex::encode(id.as_slice()) != binding.event_id)
                {
                    self.unknown(sequence, vec![])?;
                    return Err(hold());
                }
                if self.report(sequence, &outcome).is_err() {
                    // Invalid target reports cannot be accepted as evidence.
                    // A failed fsync poisons the ledger and this also refuses.
                    self.unknown(sequence, vec![])?;
                    return Err(hold());
                }
                Ok(outcome)
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
                self.unknown(sequence, if valid { failed } else { vec![] })?;
                Err(hold())
            }
            _ => {
                self.unknown(sequence, vec![])?;
                Err(hold())
            }
        }
    }
}
