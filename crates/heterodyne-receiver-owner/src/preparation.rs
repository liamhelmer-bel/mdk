//! Native private KeyPackage preparation without account activation or receive.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::key_package::{KeyPackageMetadata, key_package_metadata};
use cgka_session::{AccountDeviceSession, SessionConfig};
use cgka_traits::app_components::{NOSTR_ROUTING_COMPONENT_ID, default_group_components};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{GroupStorage, MaintenanceStorage, MessageStorage};
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::{
    KeyPackageLifecycleState, MemberId, SignedPublicationArtifact, TransportAccountActivation,
    TransportAdapter, TransportAdapterError, TransportDelivery, TransportEndpoint,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest,
};
use marmot_account::{
    AccountDeviceRuntime, KeyPackagePublication, KeyPackagePublishError, KeyPackagePublishReceipt,
    KeyPackagePublisher, StaticTransportRouting,
};
use nostr::{EventBuilder, JsonUtil, Kind, Tag, Timestamp};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};
use transport_nostr_adapter::{KIND_MARMOT_KEY_PACKAGE, NostrKeyPackagePublication};
use transport_nostr_peeler::NostrTransportEvent;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("native initialization failed; preserve exact generation")]
    Native,
    #[error("native initialization state does not match its fresh preparation contract")]
    Hold,
}

/// This type cannot open a subscription, peel a Welcome, wrap or receive MLS.
struct RefuseTransport;

#[async_trait]
impl TransportAdapter for RefuseTransport {
    async fn activate_account(
        &self,
        _: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }
    async fn sync_account_groups(
        &self,
        _: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }
    async fn deactivate_account(&self, _: &MemberId) -> Result<(), TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }
    async fn publish(
        &self,
        _: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }
    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        Err(TransportAdapterError::Closed)
    }
}

#[async_trait]
impl TransportPeeler for RefuseTransport {
    async fn peel_group_message(
        &self,
        _: &TransportMessage,
        _: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("initializer refuses ingress".into()))
    }
    async fn peel_welcome(&self, _: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("initializer refuses ingress".into()))
    }
    async fn wrap_group_message(
        &self,
        _: &EncryptedPayload,
        _: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend(
            "initializer refuses MLS publication".into(),
        ))
    }
    async fn wrap_welcome(
        &self,
        _: &EncryptedPayload,
        _: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend(
            "initializer refuses MLS publication".into(),
        ))
    }
}

struct Signer(nostr::Keys);

impl AccountIdentityProofSigner for Signer {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if request.account_identity.as_slice() != self.0.public_key().to_bytes() {
            return Err("initializer identity mismatch".into());
        }
        let event = request
            .proof_event()?
            .sign_with_keys(&self.0)
            .map_err(|_| "initializer proof signing failed")?;
        request.signature_from_signed_event(event)
    }
}

struct PrepareOnly(nostr::Keys);

fn publication(
    value: &KeyPackagePublication,
) -> Result<NostrKeyPackagePublication, KeyPackagePublishError> {
    let metadata = key_package_metadata(&value.key_package)
        .map_err(|_| KeyPackagePublishError::unexposed("invalid native package"))?;
    if metadata.protocol_profile != ProtocolProfile::Current
        || metadata.credential_identity_hex != hex::encode(value.account_id.as_slice())
    {
        return Err(KeyPackagePublishError::unexposed(
            "initializer package identity/profile mismatch",
        ));
    }
    Ok(NostrKeyPackagePublication {
        client_name: None,
        account_id: value.account_id.clone(),
        key_package: value.key_package.clone(),
        key_package_slot_id: value.slot_id.clone(),
        key_package_ref: metadata.key_package_ref_hex,
        mls_ciphersuite: format!("0x{:04x}", metadata.ciphersuite),
        mls_extensions: metadata
            .mls_extensions
            .iter()
            .map(|i| format!("0x{i:04x}"))
            .collect(),
        mls_proposals: metadata
            .mls_proposals
            .iter()
            .map(|i| format!("0x{i:04x}"))
            .collect(),
        app_components: metadata
            .app_components
            .iter()
            .filter(|i| **i >= cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START)
            .map(|i| format!("0x{i:04x}"))
            .collect(),
        publish_endpoints: value.endpoints.clone(),
    })
}

#[async_trait]
impl KeyPackagePublisher for PrepareOnly {
    async fn prepare_key_package(
        &self,
        value: KeyPackagePublication,
    ) -> Result<SignedPublicationArtifact, KeyPackagePublishError> {
        if value.account_id.as_slice() != self.0.public_key().to_bytes() {
            return Err(KeyPackagePublishError::unexposed(
                "initializer signer mismatch",
            ));
        }
        let dto = publication(&value)?
            .to_event_at(value.created_at.0)
            .map_err(|_| KeyPackagePublishError::unexposed("invalid publication"))?;
        let tags = dto
            .tags
            .into_iter()
            .map(Tag::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KeyPackagePublishError::unexposed("invalid publication tags"))?;
        let signed = EventBuilder::new(Kind::Custom(KIND_MARMOT_KEY_PACKAGE as u16), dto.content)
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(value.created_at.0))
            .sign_with_keys(&self.0)
            .map_err(|_| KeyPackagePublishError::unexposed("publication signing failed"))?;
        let event = NostrTransportEvent::from_nostr_event(&signed)
            .map_err(|_| KeyPackagePublishError::unexposed("signed publication encoding failed"))?;
        Ok(SignedPublicationArtifact {
            id: cgka_traits::MessageId::new(signed.id.to_bytes().to_vec()),
            created_at: value.created_at,
            bytes: serde_json::to_vec(&event).map_err(|_| {
                KeyPackagePublishError::unexposed("signed publication encoding failed")
            })?,
        })
    }

    async fn publish_prepared_key_package(
        &self,
        _: &KeyPackagePublication,
        _: &SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        Err(KeyPackagePublishError::unexposed(
            "local preparation has no network publisher",
        ))
    }
}

pub(crate) struct Prepared {
    pub(crate) publication: KeyPackagePublication,
    pub(crate) artifact: SignedPublicationArtifact,
    pub(crate) metadata: KeyPackageMetadata,
}

/// Exact-artifact network adapter, constructed only after durable exposure has
/// been recorded by the owning initialization operation. It owns no signer and
/// cannot create a replacement package or event.
pub(crate) struct ExactPublisher {
    prepared: Prepared,
    relay: transport_nostr_adapter::NostrKeyPackagePublisher,
    minimum: usize,
    timeout: std::time::Duration,
}

impl ExactPublisher {
    pub(crate) fn new(
        prepared: Prepared,
        relay: Arc<dyn transport_nostr_adapter::NostrRelayClient>,
        minimum: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, Error> {
        if minimum == 0
            || minimum > prepared.publication.endpoints.len()
            || timeout.is_zero()
            || timeout > std::time::Duration::from_secs(30)
        {
            return Err(Error::Hold);
        }
        Ok(Self {
            prepared,
            relay: transport_nostr_adapter::NostrKeyPackagePublisher::new(relay)
                .required_acks(minimum),
            minimum,
            timeout,
        })
    }
}

#[async_trait]
impl KeyPackagePublisher for ExactPublisher {
    async fn prepare_key_package(
        &self,
        _: KeyPackagePublication,
    ) -> Result<SignedPublicationArtifact, KeyPackagePublishError> {
        Err(KeyPackagePublishError::unexposed(
            "exact publisher cannot prepare or rotate",
        ))
    }

    async fn publish_prepared_key_package(
        &self,
        value: &KeyPackagePublication,
        artifact: &SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        // Every error in this publish entry remains possibly exposed. A caller
        // must never interpret adapter validation failure as safe regeneration.
        let exposed =
            || KeyPackagePublishError::exposed("exact publication incomplete; preserve generation");
        if value != &self.prepared.publication || artifact != &self.prepared.artifact {
            return Err(exposed());
        }
        let event: NostrTransportEvent =
            serde_json::from_slice(&artifact.bytes).map_err(|_| exposed())?;
        let signed = nostr::Event::from_json(&artifact.bytes).map_err(|_| exposed())?;
        signed.verify().map_err(|_| exposed())?;
        let dto = publication(value).map_err(|_| exposed())?;
        let outcome = tokio::time::timeout(
            self.timeout,
            self.relay.publish_prepared_key_package(&dto, &event),
        )
        .await
        .map_err(|_| exposed())?
        .map_err(|_| exposed())?;
        if outcome.message_id.as_ref() != Some(&artifact.id) {
            return Err(exposed());
        }
        let accepted: Vec<_> = outcome.accepted.into_iter().map(|r| r.endpoint).collect();
        let failed: Vec<_> = outcome.failed.into_iter().map(|r| r.endpoint).collect();
        if accepted.len() < self.minimum
            || accepted
                .iter()
                .enumerate()
                .any(|(i, e)| !value.endpoints.contains(e) || accepted[..i].contains(e))
            || failed.iter().enumerate().any(|(i, e)| {
                !value.endpoints.contains(e) || accepted.contains(e) || failed[..i].contains(e)
            })
        {
            return Err(exposed());
        }
        Ok(KeyPackagePublishReceipt { accepted, failed })
    }
}

/// Called only while the generation is unexposed. The caller must retain these
/// exact bytes durably with the KeyPackage artifact before exposure-begun. A
/// resume reads retained artifacts; it never calls this signer after exposure.
pub(crate) fn relay_lists(
    keys: &nostr::Keys,
    created_at: cgka_traits::Timestamp,
    key_package_relays: Vec<TransportEndpoint>,
    inbox_relays: Vec<TransportEndpoint>,
) -> Result<[SignedPublicationArtifact; 2], Error> {
    use transport_nostr_adapter::{NostrAccountRelayListKind, NostrAccountRelayListPublication};
    let mut result = Vec::with_capacity(2);
    for (list_kind, relays) in [
        (NostrAccountRelayListKind::Nip65, key_package_relays),
        (NostrAccountRelayListKind::Inbox, inbox_relays),
    ] {
        if relays.is_empty()
            || relays.len() > 16
            || relays
                .iter()
                .enumerate()
                .any(|(i, e)| e.0.is_empty() || e.0.len() > 2048 || relays[..i].contains(e))
        {
            return Err(Error::Hold);
        }
        let dto = NostrAccountRelayListPublication {
            account_id: MemberId::new(keys.public_key().to_bytes().to_vec()),
            list_kind,
            publish_endpoints: relays.clone(),
            relays,
        }
        .to_event()
        .map_err(|_| Error::Native)?;
        let tags = dto
            .tags
            .into_iter()
            .map(Tag::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Native)?;
        let event = EventBuilder::new(Kind::Custom(list_kind.event_kind() as u16), dto.content)
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created_at.0))
            .sign_with_keys(keys)
            .map_err(|_| Error::Native)?;
        event.verify().map_err(|_| Error::Native)?;
        let transport = NostrTransportEvent::from_nostr_event(&event).map_err(|_| Error::Native)?;
        result.push(SignedPublicationArtifact {
            id: cgka_traits::MessageId::new(event.id.to_bytes().to_vec()),
            created_at,
            bytes: serde_json::to_vec(&transport).map_err(|_| Error::Native)?,
        });
    }
    result.try_into().map_err(|_| Error::Hold)
}

/// Caller is the same admitted owner holding the fresh-generation lease. This
/// primitive neither creates filesystem custody nor grants launch authority.
pub(crate) async fn prepare(
    database: &Path,
    key: &SqlCipherKey,
    keys: nostr::Keys,
    slot: &str,
    endpoints: Vec<TransportEndpoint>,
) -> Result<Prepared, Error> {
    if slot.len() != 64
        || !slot
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || endpoints.is_empty()
        || endpoints.len() > 16
    {
        return Err(Error::Hold);
    }
    let storage = SqliteAccountStorage::open_encrypted(database, key).map_err(|_| Error::Native)?;
    if !storage.list_groups().map_err(|_| Error::Native)?.is_empty()
        || !storage
            .list_pending_application_events()
            .map_err(|_| Error::Native)?
            .is_empty()
    {
        return Err(Error::Hold);
    }
    let existing =
        cgka_engine::key_package::durably_owned_key_packages(&storage, ProtocolProfile::Current)
            .map_err(|_| Error::Native)?;
    for package in &existing {
        let metadata = key_package_metadata(package).map_err(|_| Error::Native)?;
        if metadata.protocol_profile != ProtocolProfile::Current
            || metadata.credential_identity_hex != keys.public_key().to_hex()
        {
            return Err(Error::Hold);
        }
    }
    if let Some(state) = storage.key_package_lifecycle().map_err(|_| Error::Native)? {
        if state.stable_slot_id != slot
            || state.current_key_package.is_some()
            || state.pending_replacement.as_ref().is_some_and(|p| {
                p.generation_revision != cgka_traits::maintenance::KEY_PACKAGE_GENERATION_REVISION
            })
        {
            return Err(Error::Hold);
        }
        match &state.pending_replacement {
            Some(pending) if existing.len() == 1 && existing[0] == pending.key_package => {}
            None if existing.is_empty() => {}
            _ => return Err(Error::Hold),
        }
    } else if !existing.is_empty() {
        // Opening the higher session can perform lifecycle cleanup. An unknown
        // bundle is not evidence of a recognized fresh initialization phase.
        return Err(Error::Hold);
    }
    storage.close().map_err(|_| Error::Native)?;
    let session = open_session(database, key, &keys)?;
    // Never initialize a second lifecycle or rotate a promoted/exposed package.
    match session.key_package_lifecycle().map_err(|_| Error::Native)? {
        None => session
            .put_key_package_lifecycle(&KeyPackageLifecycleState::slot_only(slot.into()))
            .map_err(|_| Error::Native)?,
        Some(ref state) if state.stable_slot_id == slot && state.current_key_package.is_none() => {}
        _ => return Err(Error::Hold),
    }
    let mut runtime = AccountDeviceRuntime::new(
        session,
        RefuseTransport,
        StaticTransportRouting::new(endpoints.clone()),
        PrepareOnly(keys),
    );
    let package = runtime
        .prepare_fresh_key_package(endpoints.clone())
        .await
        .map_err(|_| Error::Native)?;
    let state = runtime
        .session()
        .key_package_lifecycle()
        .map_err(|_| Error::Native)?
        .ok_or(Error::Hold)?;
    let pending = state.pending_replacement.ok_or(Error::Hold)?;
    let artifact = pending.signed_event.ok_or(Error::Hold)?;
    let metadata = key_package_metadata(&package).map_err(|_| Error::Native)?;
    let owned = runtime
        .session()
        .durably_owned_key_packages()
        .map_err(|_| Error::Native)?;
    if owned.len() != 1
        || owned[0] != package
        || metadata.protocol_profile != ProtocolProfile::Current
        || metadata.credential_identity_hex != hex::encode(runtime.session().self_id().as_slice())
        || pending
            .targets
            .iter()
            .map(|t| &t.endpoint)
            .ne(endpoints.iter())
        || package != pending.key_package
    {
        return Err(Error::Hold);
    }
    let publication = KeyPackagePublication {
        account_id: runtime.session().self_id().clone(),
        key_package: package,
        slot_id: slot.into(),
        created_at: pending.authored_created_at,
        endpoints,
    };
    let event: NostrTransportEvent =
        serde_json::from_slice(&artifact.bytes).map_err(|_| Error::Hold)?;
    let signed = nostr::Event::from_json(serde_json::to_string(&event).map_err(|_| Error::Hold)?)
        .map_err(|_| Error::Hold)?;
    signed.verify().map_err(|_| Error::Hold)?;
    if signed.id.to_bytes().as_slice() != artifact.id.as_slice()
        || signed.created_at.as_secs() != artifact.created_at.0
        || signed.pubkey.to_bytes().as_slice() != publication.account_id.as_slice()
    {
        return Err(Error::Hold);
    }
    Ok(Prepared {
        publication,
        artifact,
        metadata,
    })
}

fn open_session(
    database: &Path,
    key: &SqlCipherKey,
    keys: &nostr::Keys,
) -> Result<AccountDeviceSession, Error> {
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    let config = SessionConfig::new(
        database,
        SqlCipherKey::new(key.as_secret_str()).map_err(|_| Error::Native)?,
        keys.public_key().to_bytes().to_vec(),
        Box::new(RefuseTransport),
    )
    .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
    .supported_app_components(components);
    AccountDeviceSession::open(config).map_err(|_| Error::Native)
}

/// The operation must retain its generation lease and durable exposure marker.
/// Reuse native promotion only while the exact original pending artifact exists.
/// A promoted package is refused here: retry then uses the exact adapter directly.
pub(crate) async fn publish_pending(
    database: &Path,
    key: &SqlCipherKey,
    keys: &nostr::Keys,
    publisher: ExactPublisher,
) -> Result<cgka_traits::KeyPackage, Error> {
    let prepared = &publisher.prepared;
    let storage = SqliteAccountStorage::open_encrypted(database, key).map_err(|_| Error::Native)?;
    let state = storage
        .key_package_lifecycle()
        .map_err(|_| Error::Native)?
        .ok_or(Error::Hold)?;
    let pending = state.pending_replacement.ok_or(Error::Hold)?;
    let owned =
        cgka_engine::key_package::durably_owned_key_packages(&storage, ProtocolProfile::Current)
            .map_err(|_| Error::Native)?;
    if state.current_key_package.is_some()
        || state.stable_slot_id != prepared.publication.slot_id
        || keys.public_key().to_bytes().as_slice() != prepared.publication.account_id.as_slice()
        || pending.signed_event.as_ref() != Some(&prepared.artifact)
        || pending.key_package != prepared.publication.key_package
        || pending.authored_created_at != prepared.publication.created_at
        || pending
            .targets
            .iter()
            .map(|t| &t.endpoint)
            .ne(prepared.publication.endpoints.iter())
        || owned.len() != 1
        || owned[0] != prepared.publication.key_package
        || !storage.list_groups().map_err(|_| Error::Native)?.is_empty()
        || !storage
            .list_pending_application_events()
            .map_err(|_| Error::Native)?
            .is_empty()
    {
        return Err(Error::Hold);
    }
    storage.close().map_err(|_| Error::Native)?;
    let session = open_session(database, key, keys)?;
    let mut runtime = AccountDeviceRuntime::new(
        session,
        RefuseTransport,
        StaticTransportRouting::new(prepared.publication.endpoints.clone()),
        publisher,
    );
    runtime
        .publish_fresh_key_package()
        .await
        .map_err(|_| Error::Hold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_engine::key_package::durably_owned_key_packages;

    #[derive(Default)]
    struct PublicationPeer {
        mode: std::sync::atomic::AtomicU8,
        events: std::sync::Mutex<Vec<NostrTransportEvent>>,
    }

    #[async_trait]
    impl transport_nostr_adapter::NostrRelayClient for PublicationPeer {
        async fn subscribe(
            &self,
            _: transport_nostr_adapter::NostrSubscription,
        ) -> Result<(), TransportAdapterError> {
            panic!("initializer must never subscribe")
        }
        async fn unsubscribe(
            &self,
            _: transport_nostr_adapter::NostrSubscription,
        ) -> Result<(), TransportAdapterError> {
            panic!("initializer must never activate subscriptions")
        }
        async fn unsubscribe_account(&self, _: &MemberId) -> Result<(), TransportAdapterError> {
            panic!("initializer must never activate accounts")
        }
        async fn publish_event(
            &self,
            endpoints: &[TransportEndpoint],
            event: &NostrTransportEvent,
            _: usize,
        ) -> Result<transport_nostr_adapter::NostrPublishOutcome, TransportAdapterError> {
            self.events.lock().unwrap().push(event.clone());
            let accepted = match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
                0 => endpoints.to_vec(),
                1 => endpoints[..1].to_vec(),
                2 => return std::future::pending().await,
                _ => vec![TransportEndpoint::from("wss://unexpected.invalid")],
            };
            Ok(transport_nostr_adapter::NostrPublishOutcome::accepted(
                accepted,
            ))
        }
    }

    /// Native SQLCipher/preparation/signatures and the real publication adapter;
    /// the in-process peer is injected, not installed relay qualification.
    #[tokio::test]
    async fn exact_publisher_keeps_identical_bytes_across_partial_and_timeout() {
        use std::sync::atomic::Ordering;
        let temp = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("disposable-publication-test-only").unwrap();
        let prepared = prepare(
            &temp.path().join("account.sqlite3"),
            &key,
            nostr::Keys::generate(),
            &"a1".repeat(32),
            vec![
                TransportEndpoint::from("wss://one.invalid"),
                TransportEndpoint::from("wss://two.invalid"),
            ],
        )
        .await
        .unwrap();
        let value = prepared.publication.clone();
        let artifact = prepared.artifact.clone();
        let peer = Arc::new(PublicationPeer::default());
        let publisher = ExactPublisher::new(
            prepared,
            peer.clone(),
            2,
            std::time::Duration::from_millis(20),
        )
        .unwrap();
        assert_eq!(publisher.legacy_slot_id(&value.account_id).unwrap(), None);
        assert!(publisher.prepare_key_package(value.clone()).await.is_err());
        let receipt = publisher
            .publish_prepared_key_package(&value, &artifact)
            .await
            .unwrap();
        assert_eq!(receipt.accepted, value.endpoints);
        for mode in [1, 2, 3] {
            peer.mode.store(mode, Ordering::SeqCst);
            let error = publisher
                .publish_prepared_key_package(&value, &artifact)
                .await
                .unwrap_err();
            assert!(error.externally_exposed);
        }
        peer.mode.store(0, Ordering::SeqCst);
        publisher
            .publish_prepared_key_package(&value, &artifact)
            .await
            .unwrap();
        {
            let events = peer.events.lock().unwrap();
            assert_eq!(events.len(), 5);
            for event in events.iter() {
                assert_eq!(serde_json::to_vec(event).unwrap(), artifact.bytes);
            }
        }
        let mut changed = artifact.clone();
        changed.bytes.push(b' ');
        assert!(
            publisher
                .publish_prepared_key_package(&value, &changed)
                .await
                .unwrap_err()
                .externally_exposed
        );
        assert_eq!(peer.events.lock().unwrap().len(), 5);
    }

    struct JournaledFixture {
        root: tempfile::TempDir,
        _generation: crate::generation::Generation,
        database: std::path::PathBuf,
        keys: nostr::Keys,
        key: SqlCipherKey,
        prepared: Prepared,
        setup: [SignedPublicationArtifact; 2],
        relay: Arc<crate::publication::JournaledRelay>,
    }

    impl JournaledFixture {
        async fn create(
            endpoints: Vec<TransportEndpoint>,
            peer: Arc<dyn transport_nostr_adapter::NostrRelayClient>,
            minimum: usize,
            timeout: std::time::Duration,
        ) -> Self {
            use sha2::Digest;
            use std::fs::{File, OpenOptions, Permissions};
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), Permissions::from_mode(0o700)).unwrap();
            let parent = File::open(root.path()).unwrap();
            let generation_id = "b7".repeat(32);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.path().join("initialization.jsonl"))
                .unwrap();
            let mut ledger = crate::initializer::Ledger::create(
                file,
                parent.try_clone().unwrap(),
                &"f3".repeat(32),
                &generation_id,
            )
            .unwrap();
            ledger.material("d4".repeat(32)).unwrap();
            let generation =
                crate::generation::Generation::create(&parent, &generation_id).unwrap();
            let (database, keys, key) = generation.native_inputs().unwrap();
            let prepared = prepare(
                &database,
                &key,
                keys.clone(),
                &"d4".repeat(32),
                endpoints.clone(),
            )
            .await
            .unwrap();
            let setup = relay_lists(
                &keys,
                prepared.artifact.created_at,
                endpoints.clone(),
                endpoints.clone(),
            )
            .unwrap();
            let artifacts = [&setup[0], &setup[1], &prepared.artifact];
            let bindings = artifacts
                .iter()
                .zip([10002, 10050, 30443])
                .map(|(a, kind)| crate::initializer::Artifact {
                    kind,
                    event_id: hex::encode(a.id.as_slice()),
                    sha256: hex::encode(sha2::Sha256::digest(&a.bytes)),
                    targets: endpoints.iter().map(|e| e.0.clone()).collect(),
                    required_acks: minimum,
                })
                .collect::<Vec<_>>();
            let retained = generation
                .retain_publications(artifacts, &bindings)
                .unwrap();
            ledger.prepared(bindings).unwrap();
            ledger.exposure_begun().unwrap();
            let relay = Arc::new(
                crate::publication::JournaledRelay::new(
                    ledger,
                    &generation,
                    &retained,
                    peer,
                    timeout,
                )
                .unwrap(),
            );
            Self {
                root,
                _generation: generation,
                database,
                keys,
                key,
                prepared,
                setup,
                relay,
            }
        }

        fn records(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(self.root.path().join("initialization.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    #[tokio::test]
    async fn actual_sdk_loopback_publishes_exact_setup_cohort() {
        use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        // No SDK signer: the journal verifies actual retained signed bytes.
        let sdk = Arc::new(NostrSdkRelayClient::new(
            nostr_sdk::Client::builder().build(),
        ));
        let fixture = JournaledFixture::create(
            vec![endpoint.clone()],
            sdk.clone(),
            1,
            std::time::Duration::from_secs(5),
        )
        .await;
        let expected = [
            fixture.setup[0].clone(),
            fixture.setup[1].clone(),
            fixture.prepared.artifact.clone(),
        ];
        assert!(fixture.relay.published().is_err());
        for artifact in &fixture.setup {
            let event = serde_json::from_slice(&artifact.bytes).unwrap();
            let outcome = fixture
                .relay
                .publish_event(std::slice::from_ref(&endpoint), &event, 1)
                .await
                .unwrap();
            assert_eq!(outcome.accepted.len(), 1);
        }
        let publisher = ExactPublisher::new(
            fixture.prepared,
            fixture.relay.clone(),
            1,
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        publish_pending(&fixture.database, &fixture.key, &fixture.keys, publisher)
            .await
            .unwrap();
        fixture.relay.published().unwrap();
        let records: Vec<serde_json::Value> =
            std::fs::read_to_string(fixture.root.path().join("initialization.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        assert_eq!(records.last().unwrap()["phase"], "published");
        assert_eq!(
            records
                .iter()
                .filter(|r| r["attempt"]["state"] == "begun")
                .count(),
            3
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r["attempt"]["state"] == "reported")
                .count(),
            4
        );
        let observer = nostr_sdk::Client::builder().build();
        observer.add_relay(endpoint.as_str()).await.unwrap();
        observer.connect().await;
        let ids: Vec<_> = expected
            .iter()
            .map(|a| nostr::EventId::from_slice(a.id.as_slice()).unwrap())
            .collect();
        let fetched = observer
            .fetch_events(
                nostr::Filter::new().ids(ids),
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(fetched.len(), 3);
        for artifact in expected {
            let event = fetched
                .iter()
                .find(|e| e.id.to_bytes().as_slice() == artifact.id.as_slice())
                .unwrap();
            event.verify().unwrap();
            assert_eq!(event.pubkey, fixture.keys.public_key());
            assert_eq!(
                serde_json::to_vec(&NostrTransportEvent::from_nostr_event(event).unwrap()).unwrap(),
                artifact.bytes
            );
        }
        observer.shutdown().await;
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn journaled_partial_timeout_cancellation_and_same_bytes_retry() {
        use std::sync::atomic::Ordering;
        use transport_nostr_adapter::NostrRelayClient;
        let peer = Arc::new(PublicationPeer::default());
        let endpoints = vec![
            TransportEndpoint::from("wss://one.invalid"),
            TransportEndpoint::from("wss://two.invalid"),
        ];
        let fixture = JournaledFixture::create(
            endpoints.clone(),
            peer.clone(),
            2,
            std::time::Duration::from_millis(30),
        )
        .await;
        let event: NostrTransportEvent = serde_json::from_slice(&fixture.setup[0].bytes).unwrap();
        peer.mode.store(1, Ordering::SeqCst);
        assert_eq!(
            fixture
                .relay
                .publish_event(&endpoints, &event, 2)
                .await
                .unwrap()
                .accepted
                .len(),
            1
        );
        assert_eq!(
            fixture.records().last().unwrap()["accepted"][0]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        peer.mode.store(2, Ordering::SeqCst);
        assert!(
            fixture
                .relay
                .publish_event(&endpoints, &event, 2)
                .await
                .is_err()
        );
        assert_eq!(
            fixture.records().last().unwrap()["attempt"]["state"],
            "unknown"
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(5),
                fixture.relay.publish_event(&endpoints, &event, 2)
            )
            .await
            .is_err()
        );
        assert_eq!(
            fixture.records().last().unwrap()["attempt"]["state"],
            "begun"
        );
        assert!(fixture.relay.published().is_err());
        peer.mode.store(3, Ordering::SeqCst);
        assert!(
            fixture
                .relay
                .publish_event(&endpoints, &event, 2)
                .await
                .is_err()
        );
        assert_eq!(
            fixture.records().last().unwrap()["attempt"]["state"],
            "unknown"
        );
        let attempts = peer.events.lock().unwrap().len();
        let mut changed = event.clone();
        changed.content.push('x');
        assert!(
            fixture
                .relay
                .publish_event(&endpoints, &changed, 2)
                .await
                .is_err()
        );
        assert!(
            fixture
                .relay
                .publish_event(&endpoints, &event, 1)
                .await
                .is_err()
        );
        assert!(
            fixture
                .relay
                .publish_event(&endpoints[..1], &event, 2)
                .await
                .is_err()
        );
        assert_eq!(peer.events.lock().unwrap().len(), attempts);
        peer.mode.store(0, Ordering::SeqCst);
        for artifact in [
            &fixture.setup[0],
            &fixture.setup[1],
            &fixture.prepared.artifact,
        ] {
            let event = serde_json::from_slice(&artifact.bytes).unwrap();
            fixture
                .relay
                .publish_event(&endpoints, &event, 2)
                .await
                .unwrap();
        }
        fixture.relay.published().unwrap();
        assert_eq!(fixture.records().last().unwrap()["phase"], "published");
        let events = peer.events.lock().unwrap();
        for actual in events.iter().take(attempts + 1) {
            assert_eq!(serde_json::to_vec(actual).unwrap(), fixture.setup[0].bytes);
        }
    }

    #[tokio::test]
    async fn native_promotion_requires_threshold_and_refuses_promoted_reentry() {
        use std::sync::atomic::Ordering;
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("account.sqlite3");
        let key = SqlCipherKey::new("disposable-native-promotion-test-only").unwrap();
        let keys = nostr::Keys::generate();
        let slot = "b2".repeat(32);
        let endpoints = vec![
            TransportEndpoint::from("wss://one.invalid"),
            TransportEndpoint::from("wss://two.invalid"),
        ];
        let peer = Arc::new(PublicationPeer::default());
        let prepared = prepare(&database, &key, keys.clone(), &slot, endpoints.clone())
            .await
            .unwrap();
        let original = prepared.artifact.clone();
        peer.mode.store(1, Ordering::SeqCst);
        let publisher =
            ExactPublisher::new(prepared, peer.clone(), 2, std::time::Duration::from_secs(1))
                .unwrap();
        assert!(
            publish_pending(&database, &key, &keys, publisher)
                .await
                .is_err()
        );
        let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let state = storage.key_package_lifecycle().unwrap().unwrap();
        assert!(state.current_key_package.is_none());
        assert_eq!(
            state.pending_replacement.unwrap().signed_event.unwrap(),
            original
        );
        storage.close().unwrap();
        let prepared = prepare(&database, &key, keys.clone(), &slot, endpoints.clone())
            .await
            .unwrap();
        assert_eq!(prepared.artifact, original);
        let retained_for_direct_retry =
            prepare(&database, &key, keys.clone(), &slot, endpoints.clone())
                .await
                .unwrap();
        peer.mode.store(0, Ordering::SeqCst);
        let publisher =
            ExactPublisher::new(prepared, peer.clone(), 2, std::time::Duration::from_secs(1))
                .unwrap();
        let package = publish_pending(&database, &key, &keys, publisher)
            .await
            .unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let state = storage.key_package_lifecycle().unwrap().unwrap();
        assert!(state.pending_replacement.is_none());
        assert_eq!(
            durably_owned_key_packages(&storage, ProtocolProfile::Current).unwrap(),
            vec![package]
        );
        assert!(state.current_key_package.is_some());
        storage.close().unwrap();
        let value = retained_for_direct_retry.publication.clone();
        let publisher = ExactPublisher::new(
            retained_for_direct_retry,
            peer.clone(),
            2,
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        publisher
            .publish_prepared_key_package(&value, &original)
            .await
            .unwrap();
        assert!(
            publish_pending(&database, &key, &keys, publisher)
                .await
                .is_err()
        );
        assert_eq!(peer.events.lock().unwrap().len(), 3);
        assert!(
            prepare(&database, &key, keys, &slot, endpoints)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn real_private_package_and_signed_bytes_survive_exact_local_resume() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("account.sqlite3");
        let key = SqlCipherKey::new("test-only-disposable-encrypted-account").unwrap();
        let keys = nostr::Keys::generate();
        let identity = keys.public_key();
        let slot = "a1".repeat(32);
        let endpoints = vec![TransportEndpoint::from("wss://relay.invalid")];
        let first = prepare(&database, &key, keys.clone(), &slot, endpoints.clone())
            .await
            .unwrap();
        assert_eq!(first.metadata.protocol_profile, ProtocolProfile::Current);
        assert_eq!(first.metadata.credential_identity_hex, identity.to_hex());
        assert!(
            first
                .metadata
                .app_components
                .contains(&NOSTR_ROUTING_COMPONENT_ID)
        );
        let second = prepare(&database, &key, keys.clone(), &slot, endpoints.clone())
            .await
            .unwrap();
        assert_eq!(first.artifact, second.artifact);
        assert_eq!(first.publication, second.publication);
        assert!(
            prepare(
                &database,
                &key,
                nostr::Keys::generate(),
                &slot,
                endpoints.clone()
            )
            .await
            .is_err()
        );
        let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        assert!(storage.list_groups().unwrap().is_empty());
        assert!(
            storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
        let owned = durably_owned_key_packages(&storage, ProtocolProfile::Current).unwrap();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0], first.publication.key_package);
        storage.close().unwrap();
        assert!(
            prepare(
                &database,
                &key,
                keys.clone(),
                &"b2".repeat(32),
                endpoints.clone()
            )
            .await
            .is_err()
        );
        assert!(
            prepare(
                &database,
                &key,
                keys,
                &slot,
                vec![TransportEndpoint::from("wss://changed.invalid")]
            )
            .await
            .is_err()
        );
        let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let state = storage.key_package_lifecycle().unwrap().unwrap();
        assert_eq!(
            state.pending_replacement.unwrap().signed_event.unwrap(),
            first.artifact
        );
        storage.close().unwrap();
    }

    #[tokio::test]
    async fn preparation_transport_cannot_receive_activate_or_publish() {
        assert!(RefuseTransport.receive().await.is_err());
        assert!(
            RefuseTransport
                .deactivate_account(&MemberId::new(vec![1; 32]))
                .await
                .is_err()
        );
        let key = SqlCipherKey::new("test-only-key").unwrap();
        let temp = tempfile::tempdir().unwrap();
        let prepared = prepare(
            &temp.path().join("account.sqlite3"),
            &key,
            nostr::Keys::generate(),
            &"a1".repeat(32),
            vec![TransportEndpoint::from("wss://relay.invalid")],
        )
        .await
        .unwrap();
        let result = PrepareOnly(nostr::Keys::generate())
            .publish_prepared_key_package(&prepared.publication, &prepared.artifact)
            .await
            .unwrap_err();
        assert!(!result.externally_exposed);
    }
}
