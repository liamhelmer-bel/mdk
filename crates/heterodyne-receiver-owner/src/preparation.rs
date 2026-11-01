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
    let identity = keys.public_key().to_bytes().to_vec();
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    let config = SessionConfig::new(
        database,
        SqlCipherKey::new(key.as_secret_str()).map_err(|_| Error::Native)?,
        identity,
        Box::new(RefuseTransport),
    )
    .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
    .supported_app_components(components);
    let session = AccountDeviceSession::open(config).map_err(|_| Error::Native)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_engine::key_package::durably_owned_key_packages;

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
