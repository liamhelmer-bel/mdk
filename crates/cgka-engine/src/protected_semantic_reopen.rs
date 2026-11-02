//! Source-owned semantic continuation. External DTOs never select authority.
use super::*;
use crate::{Engine, protected_recovery::Journal};
use std::fs::File;
/// Both descriptors are supplied by the same eventual protected owning opener.
/// A public path/descriptor provenance factory is deliberately not installed.
pub(super) struct ReopenFiles {
    pub(super) expiry: File,
    pub(super) cache: File,
    pub(super) mode: super::super::ReceiverMode,
}

impl<S: StorageProvider + 'static> SemanticFactory<S> {
    pub(super) fn ordered(&self) -> Result<&Journal, ReceiverHold> {
        match &self.receiver.journal {
            super::super::ReceiverJournal::Ordered(j) => Ok(j),
            _ => Err(ReceiverHold::Configuration),
        }
    }
    /// Actual native/current-policy verification precedes stream reconstruction;
    /// exact native plaintext acknowledgments happen only after both succeed.
    pub(super) fn reopen(
        engine: Engine<S>,
        group: cgka_traits::types::GroupId,
        operators: Vec<MemberId>,
        journal: Journal,
        transport: NostrTransportAdapter,
        endpoints: Vec<TransportEndpoint>,
        files: ReopenFiles,
    ) -> Result<Self, ReceiverHold> {
        let receiver = ProtectedReceiver::reopen_ordered_for_mode(
            engine, group, operators, journal, files.mode,
        )?;
        let pending = receiver.check_reopened_pending()?;
        let mut factory =
            Self::new(receiver, transport, endpoints)?.with_expiry_profile(files.expiry)?;
        factory.enable_reopened_catalog(files.cache)?;
        factory.receiver.acknowledge_reopened_pending(&pending)?;
        factory.expire()?;
        factory.sync_catalog()?;
        Ok(factory)
    }
    pub(super) fn enable_catalog(&mut self, directory: File) -> Result<(), ReceiverHold> {
        if self.catalog.is_some() || self.expiry_profile.is_none() || self.held {
            return Err(ReceiverHold::Configuration);
        }
        let catalog = catalog::Catalog::rebuild(
            self.ordered()?,
            directory,
            &self.policy()?,
            &self.endpoints,
        )?;
        self.install_catalog(catalog)
    }
    fn enable_reopened_catalog(&mut self, directory: File) -> Result<(), ReceiverHold> {
        let catalog = catalog::Catalog::rebuild_for_reopen(
            self.ordered()?,
            directory,
            &self.policy()?,
            &self.endpoints,
        )?;
        let pending = catalog.unprojected.clone();
        self.install_catalog(catalog)?;
        self.expire()?;
        if let Some(value) = pending {
            let c: super::super::RetainedCandidate =
                serde_json::from_value(value).map_err(|_| ReceiverHold::Malformed)?;
            let candidate = AuthenticatedCandidate {
                sequence: c.sequence,
                received_at_unix_ms: c.received_at_unix_ms,
                group: c.group,
                message_id: c.message_id,
                source_epoch: c.source_epoch,
                sender: c.sender,
                application: c.application,
            };
            self.held = true;
            if self.hydrate_targets(&candidate)? {
                self.classify(candidate)?;
            }
        }
        Ok(())
    }
    fn install_catalog(&mut self, catalog: catalog::Catalog) -> Result<(), ReceiverHold> {
        let unanswered: Vec<_> = catalog.unanswered.keys().cloned().collect();
        self.catalog = Some(catalog);
        self.asks.clear();
        self.seen_candidates.clear();
        self.removals.clear();
        for id in unanswered {
            self.load_retained(&id)?;
        }
        Ok(())
    }
    pub(super) fn sync_catalog(&mut self) -> Result<(), ReceiverHold> {
        if let Some(catalog) = self.catalog.take() {
            self.held = true;
            let next = catalog.advance(self.ordered()?, &self.policy()?, &self.endpoints)?;
            self.catalog = Some(next);
            self.held = false;
        }
        Ok(())
    }
    pub(super) fn catalog_start(&mut self) -> Result<(), ReceiverHold> {
        if self.catalog.is_none() {
            return Ok(());
        }
        self.sync_catalog()?;
        self.asks
            .retain(|_, a| a.receipt.is_none() && !a.consumed && !a.conflicted && !a.expired);
        self.seen_candidates.clear();
        self.removals.clear();
        Ok(())
    }
    pub(super) fn catalog_has_ask(&self, id: &str) -> Result<bool, ReceiverHold> {
        match &self.catalog {
            Some(catalog) => Ok(catalog.retained_ask(id)?.is_some()),
            None => Ok(false),
        }
    }
    pub(super) fn load_retained(&mut self, id: &str) -> Result<(), ReceiverHold> {
        if self.asks.contains_key(id) {
            return Ok(());
        }
        let Some(catalog) = &self.catalog else {
            return Ok(());
        };
        let Some(ask) = catalog.retained_ask(id)? else {
            return Ok(());
        };
        let record = self
            .ordered()?
            .source_at(ask.original_sequence)
            .map_err(|_| ReceiverHold::Journal)?;
        let value = &record.body["value"];
        let o = &value["original"];
        if ask.id != id
            || value["schema"] != "semantic-original.v2"
            || o["ask_id"].as_str() != Some(id)
            || value["policy_sha256"].as_str() != Some(ask.policy_sha256.as_str())
            || value["expires_at_unix_ms"].as_u64() != Some(ask.expiry)
        {
            return Err(ReceiverHold::ChangedState);
        }
        let bytes = |key: &str| {
            hex::decode(o[key].as_str().ok_or(ReceiverHold::Malformed)?)
                .map_err(|_| ReceiverHold::Malformed)
        };
        let original = OriginalAsk {
            ask_id: ask.id.clone(),
            expected_group: serde_json::from_value(o["expected_group"].clone())
                .map_err(|_| ReceiverHold::Malformed)?,
            operation: bytes("operation")?,
            operation_canonical: bytes("operation_canonical")?,
            original_request: bytes("original_request")?,
            card_chunks: serde_json::from_value(o["card_chunks"].clone())
                .map_err(|_| ReceiverHold::Malformed)?,
        };
        if original.expected_group != self.receiver.group
            || digest(&original.operation) != ask.original_sha256
            || digest(&original.operation_canonical) != ask.packet_sha256
            || digest(&original.original_request) != ask.request_sha256
            || digest(
                &serde_json::to_vec(&original.card_chunks).map_err(|_| ReceiverHold::Malformed)?,
            ) != ask.cards_sha256
        {
            return Err(ReceiverHold::ChangedState);
        }
        let receipt = if let Some(sequence) = ask.decision_sequence {
            let source = self
                .ordered()?
                .source_at(sequence)
                .map_err(|_| ReceiverHold::Journal)?;
            let r = &source.body["value"]["receipt"];
            if source.body["value"]["schema"] != "semantic-decision.v1"
                || r["ask_id"].as_str() != Some(id)
                || r["operation_sha256"].as_str() != Some(ask.original_sha256.as_str())
                || r["packet_sha256"].as_str() != Some(ask.packet_sha256.as_str())
                || r["request_sha256"].as_str() != Some(ask.request_sha256.as_str())
                || r["cards_sha256"].as_str() != Some(ask.cards_sha256.as_str())
                || r["policy_sha256"].as_str() != Some(ask.policy_sha256.as_str())
            {
                return Err(ReceiverHold::ChangedState);
            }
            catalog.check_retained_candidate(self.ordered()?, &r["authenticated_candidate"])?;
            // Readback remains confined to this fully checked owning path. No
            // public Deserialize or constructor can turn a DTO into authority.
            let c: super::super::RetainedCandidate =
                serde_json::from_value(r["authenticated_candidate"].clone())
                    .map_err(|_| ReceiverHold::Malformed)?;
            if c.group != self.receiver.group
                || !self.receiver.operators.contains(&c.sender)
                || r["operator"]
                    != serde_json::to_value(&c.sender).map_err(|_| ReceiverHold::Malformed)?
                || r["sequence"].as_u64() != Some(c.sequence)
            {
                return Err(ReceiverHold::ChangedState);
            }
            Some(SemanticReceipt {
                sequence: c.sequence,
                ask_id: ask.id.clone(),
                operation_sha256: ask.original_sha256.clone(),
                packet_sha256: ask.packet_sha256.clone(),
                request_sha256: ask.request_sha256.clone(),
                cards_sha256: ask.cards_sha256.clone(),
                policy_sha256: ask.policy_sha256.clone(),
                operator: c.sender.clone(),
                decision: match r["decision"].as_str() {
                    Some("Approve") => Decision::Approve,
                    Some("Deny") => Decision::Deny,
                    _ => return Err(ReceiverHold::Malformed),
                },
                authenticated_candidate: AuthenticatedCandidate {
                    sequence: c.sequence,
                    received_at_unix_ms: c.received_at_unix_ms,
                    group: c.group,
                    message_id: c.message_id,
                    source_epoch: c.source_epoch,
                    sender: c.sender,
                    application: c.application,
                },
            })
        } else {
            None
        };
        self.asks.insert(
            id.into(),
            RetainedAsk {
                original,
                policy_sha256: ask.policy_sha256,
                app_ids: ask.app_ids,
                receipt,
                consumed: ask.consumed,
                conflicted: ask.conflicted,
                expires_at_unix_ms: Some(ask.expiry),
                expired: ask.disposition == catalog::Disposition::Expired,
            },
        );
        Ok(())
    }
    pub(super) fn hydrate_candidate(
        &mut self,
        candidate: &AuthenticatedCandidate,
    ) -> Result<bool, ReceiverHold> {
        let Some(catalog) = &self.catalog else {
            return Ok(true);
        };
        if catalog.retained_candidate(&candidate.message_id)? {
            return Err(ReceiverHold::ChangedState);
        }
        self.hydrate_targets(candidate)
    }
    fn hydrate_targets(
        &mut self,
        candidate: &AuthenticatedCandidate,
    ) -> Result<bool, ReceiverHold> {
        let Some(catalog) = &self.catalog else {
            return Ok(true);
        };
        let relevant = catalog
            .relevant(&serde_json::to_value(candidate).map_err(|_| ReceiverHold::Malformed)?)?;
        let now = self.receiver.checked_now()?;
        let mut ids = Vec::new();
        for id in relevant {
            let ask = self
                .catalog
                .as_ref()
                .ok_or(ReceiverHold::ChangedState)?
                .retained_ask(&id)?
                .ok_or(ReceiverHold::ChangedState)?;
            if now >= ask.expiry
                && matches!(
                    ask.disposition,
                    catalog::Disposition::Awaiting | catalog::Disposition::Approved
                )
            {
                if !self.asks.get(&id).is_some_and(|a| a.expired) {
                    self.receiver.record(serde_json::json!({"schema":"semantic-expired.v1", "ask_id":id, "at_unix_ms":now}))?;
                    if let Some(a) = self.asks.get_mut(&id) {
                        a.expired = true;
                    }
                }
                continue;
            }
            ids.push(id);
        }
        if ids.len() > 1 {
            // Unsupported multi-ask input creates one scoped durable objection.
            // Compact terminal rows suffice: do not load historical full cards.
            self.retain_removal(candidate)?;
            self.receiver.record(serde_json::json!({"schema":"semantic-conflict.v1","ask_ids":ids,"authenticated_candidate":candidate}))?;
            for id in &ids {
                if let Some(ask) = self.asks.get_mut(id) {
                    ask.conflicted = true;
                }
            }
            self.held = false;
            self.sync_catalog()?;
            return Ok(false);
        }
        let removed = self
            .catalog
            .as_ref()
            .ok_or(ReceiverHold::ChangedState)?
            .retained_removal(
                &serde_json::to_value(&candidate.sender).map_err(|_| ReceiverHold::Malformed)?,
                &candidate.application.id,
            )?;
        if removed {
            self.removals.insert((
                Some(hex::encode(candidate.sender.as_slice())),
                candidate.application.id.to_ascii_lowercase(),
            ));
        }
        for id in ids {
            self.load_retained(&id)?;
        }
        Ok(true)
    }
}
