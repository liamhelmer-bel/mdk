//! Private source-only semantic receipts. No public authority or runtime factory.
//! Exact rendering must come from the protected pinned admind producer, not agents.
use super::{AuthenticatedCandidate, ProtectedReceiver, ReceiverHold};
use cgka_traits::{
    TransportAdapter, TransportEndpoint, TransportPublishRequest, TransportPublishTarget,
    app_event::{
        MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
        MarmotAppEvent,
    },
    engine::{CgkaEngine, SendIntent, SendResult},
    storage::StorageProvider,
    transport::TransportMessage,
    types::MemberId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use transport_nostr_adapter::NostrTransportAdapter;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Source-owned producer input, never deserialized as authority. Original bytes
/// are retained, not reconstructed from a summary. Rendering enrollment is separate.
#[derive(Serialize)]
struct OriginalAsk {
    ask_id: String,
    expected_group: cgka_traits::types::GroupId,
    #[serde(serialize_with = "serialize_hex")]
    operation: Vec<u8>,
    #[serde(serialize_with = "serialize_hex")]
    operation_canonical: Vec<u8>,
    #[serde(serialize_with = "serialize_hex")]
    original_request: Vec<u8>,
    card_chunks: Vec<String>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
enum Decision {
    Approve,
    Deny,
}
#[derive(Debug, Serialize)]
struct SemanticReceipt {
    sequence: u64,
    ask_id: String,
    operation_sha256: String,
    packet_sha256: String,
    request_sha256: String,
    cards_sha256: String,
    policy_sha256: String,
    operator: MemberId,
    decision: Decision,
    authenticated_candidate: AuthenticatedCandidate,
}
struct RetainedAsk {
    original: OriginalAsk,
    policy_sha256: String,
    app_ids: Vec<String>,
    receipt: Option<SemanticReceipt>,
    consumed: bool,
    conflicted: bool,
}
/// All methods remain private; no plaintext evidence import or delivery flag.
struct SemanticFactory<S: StorageProvider + 'static> {
    receiver: ProtectedReceiver<S>,
    transport: NostrTransportAdapter,
    endpoints: Vec<TransportEndpoint>,
    asks: BTreeMap<String, RetainedAsk>,
    seen_candidates: BTreeSet<String>,
    held: bool,
}
impl<S: StorageProvider + 'static> SemanticFactory<S> {
    fn new(
        receiver: ProtectedReceiver<S>,
        transport: NostrTransportAdapter,
        endpoints: Vec<TransportEndpoint>,
    ) -> Result<Self, ReceiverHold> {
        if endpoints.is_empty()
            || endpoints.len() > 16
            || endpoints.iter().collect::<BTreeSet<_>>().len() != endpoints.len()
        {
            return Err(ReceiverHold::Configuration);
        }
        Ok(Self {
            receiver,
            transport,
            endpoints,
            asks: BTreeMap::new(),
            seen_candidates: BTreeSet::new(),
            held: false,
        })
    }
    fn policy(&self) -> Result<String, ReceiverHold> {
        // Exact protected configured policy, not a caller revision/current flag.
        serde_json::to_vec(&(&self.receiver.group, &self.receiver.operators))
            .map(|b| digest(&b))
            .map_err(|_| ReceiverHold::Malformed)
    }
    async fn post(&mut self, original: OriginalAsk) -> Result<(), ReceiverHold> {
        // One finite deadline for the complete card, never 30 seconds per part.
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.post_inner(original),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                self.held = true;
                Err(ReceiverHold::Engine)
            }
        }
    }
    async fn post_inner(&mut self, original: OriginalAsk) -> Result<(), ReceiverHold> {
        if self.held || self.receiver.latched {
            return Err(ReceiverHold::Latched);
        }
        if self.asks.values().filter(|a| a.receipt.is_none()).count() >= 100
            || original.expected_group != self.receiver.group
            || self.asks.contains_key(&original.ask_id)
            || !valid_ask_id(&original.ask_id)
            || original.operation.is_empty()
            || original.operation.len() > 64 * 1024
            || original.operation_canonical.is_empty()
            || original.operation_canonical.len() > 64 * 1024
            || original.original_request.is_empty()
            || original.original_request.len() > 64 * 1024
            || original.card_chunks.is_empty()
            || original.card_chunks.len() > 16
            || original
                .card_chunks
                .iter()
                .any(|p| p.is_empty() || p.len() > 24_000)
            || original.card_chunks.iter().map(String::len).sum::<usize>() > 96_000
        {
            return Err(ReceiverHold::Configuration);
        }
        let policy = self.policy()?;
        // Validate the largest retained input before sending or latching.
        if serde_json::to_vec(&original)
            .map_err(|_| ReceiverHold::Malformed)?
            .len()
            > super::MAX_RECORD
        {
            return Err(ReceiverHold::Capacity);
        }
        self.held = true;
        self.receiver
            .record(serde_json::json!({"schema":"semantic-original.v1",
            "original":original,"policy_sha256":policy}))?;
        let mut app_ids = Vec::new();
        for (index, text) in original.card_chunks.iter().enumerate() {
            let event = MarmotAppEvent::new(
                hex::encode(self.receiver.engine.self_id().as_slice()),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| ReceiverHold::Journal)?
                    .as_secs(),
                MARMOT_APP_EVENT_KIND_CHAT,
                vec![],
                text.clone(),
            );
            if self
                .asks
                .values()
                .any(|ask| ask.app_ids.contains(&event.id))
                || app_ids.contains(&event.id)
            {
                return Err(ReceiverHold::ChangedState);
            }
            let payload = event.encode().map_err(|_| ReceiverHold::Malformed)?;
            let result = self
                .receiver
                .engine
                .send(SendIntent::AppMessage {
                    group_id: self.receiver.group.clone(),
                    payload,
                    expected_epoch: None,
                })
                .await
                .map_err(|_| ReceiverHold::Engine)?;
            let SendResult::ApplicationMessage {
                msg,
                app_event_id,
                group_id,
                ..
            } = result
            else {
                return Err(ReceiverHold::ChangedState);
            };
            if group_id != self.receiver.group || app_event_id != event.id {
                return Err(ReceiverHold::ChangedState);
            }
            let expected = msg.id.clone();
            let transport_group_id = match &msg.envelope {
                cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } => {
                    transport_group_id.clone()
                }
                _ => return Err(ReceiverHold::ChangedState),
            };
            self.receiver
                .record(serde_json::json!({"schema":"semantic-outbound.v1",
                "ask_id":original.ask_id,"part":index,"app_event_id":app_event_id,"wire":msg}))?;
            let report = self
                .transport
                .publish(TransportPublishRequest {
                    account_id: self.receiver.engine.self_id(),
                    message: msg,
                    target: TransportPublishTarget::Group {
                        group_id,
                        transport_group_id,
                        endpoints: self.endpoints.clone(),
                    },
                    required_acks: 1,
                })
                .await
                .map_err(|_| ReceiverHold::Engine)?;
            if report.message_id != expected
                || report.required_acks != 1
                || !report.met_required_acks()
                || report
                    .accepted
                    .iter()
                    .any(|r| !self.endpoints.contains(&r.endpoint))
                || report
                    .accepted
                    .iter()
                    .map(|r| &r.endpoint)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != report.accepted.len()
            {
                return Err(ReceiverHold::ChangedState);
            }
            self.receiver
                .record(serde_json::json!({"schema":"semantic-published.v1",
                "ask_id":original.ask_id,"part":index,"report":report}))?;
            app_ids.push(app_event_id);
        }
        self.receiver
            .record(serde_json::json!({"schema":"semantic-card-complete.v1",
            "ask_id":original.ask_id,"app_ids":app_ids,"policy_sha256":policy}))?;
        self.asks.insert(
            original.ask_id.clone(),
            RetainedAsk {
                original,
                policy_sha256: policy,
                app_ids,
                receipt: None,
                consumed: false,
                conflicted: false,
            },
        );
        self.held = false;
        Ok(())
    }
    async fn ingest(&mut self, wire: TransportMessage) -> Result<Option<String>, ReceiverHold> {
        if self.held {
            return Err(ReceiverHold::Latched);
        }
        self.held = true;
        let result = self.receiver.ingest(wire).await;
        // A bounded refusal before the native boundary has no uncertain effect.
        // Do not turn oversized unrelated transport input into a global lock.
        if result.is_err() && !self.receiver.latched {
            self.held = false;
        }
        let Some(candidate) = result? else {
            self.held = false;
            return Ok(None);
        };
        // A receipt is made only by this actual ingestion path, never from a DTO.
        if !self.seen_candidates.insert(candidate.message_id.clone()) {
            return Err(ReceiverHold::ChangedState);
        }
        let app = &candidate.application;
        // Determine relevance before validating tag shape. Optional relay hints
        // and hex case are not authority; unrelated traffic must not latch asks.
        let targets: Vec<_> = app
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|s| s == "e"))
            .filter_map(|t| t.get(1))
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let command_id = if app.kind == MARMOT_APP_EVENT_KIND_CHAT {
            let mut words = app.content.split_whitespace();
            match (words.next(), words.next()) {
                (Some("!answer"), Some(id)) => Some(id.to_ascii_lowercase()),
                _ => None,
            }
        } else {
            None
        };
        let matches: Vec<_> = self
            .asks
            .iter()
            .filter(|(id, r)| {
                command_id.as_ref() == Some(*id)
                    || targets
                        .iter()
                        .any(|t| r.app_ids.iter().any(|id| id.eq_ignore_ascii_case(t)))
                    || (app.kind == MARMOT_APP_EVENT_KIND_DELETE
                        && r.receipt.as_ref().is_some_and(|r| {
                            r.operator == candidate.sender
                                && targets.iter().any(|t| {
                                    r.authenticated_candidate
                                        .application
                                        .id
                                        .eq_ignore_ascii_case(t)
                                })
                        }))
            })
            .map(|(id, _)| id.clone())
            .collect();
        if matches.is_empty() {
            self.held = false;
            return Ok(None);
        }
        // A relevant unsupported reply/deletion or ambiguous target is a scoped
        // conflict, never silent permission to use an earlier approval. It does
        // not impose a global latch on unrelated asks.
        let supported_reaction =
            app.kind == MARMOT_APP_EVENT_KIND_REACTION && targets.len() == 1 && matches.len() == 1;
        let decision = emoji_action(&app.content);
        if !supported_reaction
            || (self.asks[&matches[0]].receipt.is_some() || self.asks[&matches[0]].conflicted)
        {
            self.receiver
                .record(serde_json::json!({"schema":"semantic-conflict.v1",
                "ask_ids":matches,"authenticated_candidate":candidate}))?;
            for id in &matches {
                self.asks
                    .get_mut(id)
                    .ok_or(ReceiverHold::ChangedState)?
                    .conflicted = true;
            }
            self.held = false;
            return Ok(None);
        }
        let Some(decision) = decision else {
            self.held = false;
            return Ok(None);
        };
        let policy = self.policy()?;
        let key = &matches[0];
        let ask = &self.asks[key];
        if ask.conflicted
            || ask.receipt.is_some()
            || ask.consumed
            || ask.policy_sha256 != policy
            || !self.receiver.operators.contains(&candidate.sender)
        {
            return Err(ReceiverHold::ChangedState);
        }
        let receipt = SemanticReceipt {
            sequence: candidate.sequence,
            ask_id: key.clone(),
            operation_sha256: digest(&ask.original.operation),
            packet_sha256: digest(&ask.original.operation_canonical),
            request_sha256: digest(&ask.original.original_request),
            cards_sha256: digest(
                &serde_json::to_vec(&ask.original.card_chunks)
                    .map_err(|_| ReceiverHold::Malformed)?,
            ),
            policy_sha256: policy,
            operator: candidate.sender.clone(),
            decision,
            authenticated_candidate: candidate,
        };
        self.receiver
            .record(serde_json::json!({"schema":"semantic-decision.v1","receipt":receipt}))?;
        self.asks
            .get_mut(key)
            .ok_or(ReceiverHold::ChangedState)?
            .receipt = Some(receipt);
        self.held = false;
        Ok(Some(key.clone()))
    }
    /// One-use evidence lookup. Caller IDs/digests select retained facts; they do not create them.
    fn consume(
        &mut self,
        ask_id: &str,
        expected_operation_sha256: &str,
    ) -> Result<&SemanticReceipt, ReceiverHold> {
        if self.held || self.receiver.latched {
            return Err(ReceiverHold::Latched);
        }
        let policy = self.policy()?;
        let ask = self.asks.get(ask_id).ok_or(ReceiverHold::Configuration)?;
        let r = ask.receipt.as_ref().ok_or(ReceiverHold::ChangedState)?;
        if ask.conflicted
            || ask.consumed
            || r.decision != Decision::Approve
            || r.policy_sha256 != policy
            || r.operation_sha256 != expected_operation_sha256
            || !self.receiver.operators.contains(&r.operator)
        {
            return Err(ReceiverHold::ChangedState);
        }
        self.held = true;
        self.receiver
            .record(serde_json::json!({"schema":"semantic-consumed.v1",
            "ask_id":ask_id,"operation_sha256":expected_operation_sha256,"sequence":r.sequence}))?;
        let ask = self
            .asks
            .get_mut(ask_id)
            .ok_or(ReceiverHold::ChangedState)?;
        ask.consumed = true;
        self.held = false;
        ask.receipt.as_ref().ok_or(ReceiverHold::ChangedState)
    }
}
fn serialize_hex<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}
fn valid_ask_id(s: &str) -> bool {
    s.len() == 4
        && s.bytes()
            .all(|b| b"23456789abcdefghjkmnpqrstuvwxyz".contains(&b))
}
/// Existing admind reaction vocabulary restricted to the release-safe non-heart subset.
fn emoji_action(s: &str) -> Option<Decision> {
    let s = s.strip_suffix('\u{fe0f}').unwrap_or(s);
    let base = s.trim_end_matches([
        '\u{1f3fb}',
        '\u{1f3fc}',
        '\u{1f3fd}',
        '\u{1f3fe}',
        '\u{1f3ff}',
    ]);
    match (s, base) {
        ("✅", _) => Some(Decision::Approve),
        ("❌", _) => Some(Decision::Deny),
        (_, "👍") if s.chars().count() <= 2 => Some(Decision::Approve),
        (_, "👎") if s.chars().count() <= 2 => Some(Decision::Deny),
        _ => None,
    }
}
#[cfg(test)]
#[path = "protected_semantic_tests.rs"]
mod tests;
