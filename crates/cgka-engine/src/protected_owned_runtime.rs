//! Fixed source-owned process entry. Root-enrolled FD publisher is not installed.
//! No stdin/JSON approval importer exists; the only decision comes from Engine.
use super::*;
use crate::{
    EngineBuilder,
    protected_recovery::{Enrollment, Journal, OwnedFiles},
};
use cgka_traits::GroupId;
use cgka_traits::{TransportAccountActivation, TransportGroupSubscription};
use serde::{Deserialize, Serialize};
use std::os::fd::OwnedFd;
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};
use transport_nostr_adapter::NostrSdkRelayClient;
use transport_nostr_peeler::NostrMlsPeeler;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: String,
    receiver_uid: u32,
    consumer_uid: u32,
    enrollment: Enrollment,
    endpoints: Vec<TransportEndpoint>,
    transport_group: Vec<u8>,
    python: PathBuf,
    product_source: PathBuf,
    purelib: PathBuf,
    installation: receiver_installation_verifier::reference::Installation,
    // Exact Product deadline must also pass the independently retained expiry profile.
    wait_seconds: u32,
}
fn inherited(fd: i32) -> Result<File, ReceiverHold> {
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(ReceiverHold::Configuration);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn read(file: &File, limit: u64) -> Result<Vec<u8>, ReceiverHold> {
    owned_producer::read_retained(file, limit)
}
struct Signer(nostr::Keys);
impl crate::account_identity_proof::AccountIdentityProofSigner for Signer {
    fn sign_account_identity_proof(
        &self,
        r: &crate::account_identity_proof::AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.0.public_key().to_bytes().as_slice() != r.account_identity.as_slice() {
            return Err("account mismatch".into());
        }
        let event = r
            .proof_event()?
            .sign_with_keys(&self.0)
            .map_err(|e| e.to_string())?;
        r.signature_from_signed_event(event)
    }
}
// The fixed fresh and resumed receiver both require routed current groups.
// Keep this opt-in local: the generic EngineBuilder default remains unchanged.
fn owned_routed_engine(
    storage: SqliteAccountStorage,
    keys: nostr::Keys,
    template: crate::protected_capability_policy::Template,
) -> Result<crate::Engine<SqliteAccountStorage>, ReceiverHold> {
    EngineBuilder::new(storage)
        .supported_app_components(template.components())
        .feature_registry(template.registry())
        .identity(keys.public_key().to_bytes().to_vec())
        .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
        .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(keys)))
        .build()
        .map_err(|_| ReceiverHold::Engine)
}
/// This exported *entry* has no authority-bearing arguments or constructors.
/// Root profile + owned inherited descriptors are the only startup contract.
pub(crate) fn entry() -> bool {
    if std::env::args_os().count() != 1 {
        return false;
    }
    let result = (|| {
        let profile_file = inherited(3)?;
        if profile_file
            .metadata()
            .map_err(|_| ReceiverHold::Configuration)?
            .uid()
            != 0
        {
            return Err(ReceiverHold::Configuration);
        }
        let raw = read(&profile_file, 65536)?;
        let profile: Profile = serde_json::from_slice(&raw).map_err(|_| ReceiverHold::Malformed)?;
        if profile.schema != "heterodyne-protected-receiver-process.v3"
            || profile.receiver_uid != unsafe { libc::geteuid() }
            || profile.consumer_uid == 0
            || profile.consumer_uid == profile.receiver_uid
            || profile.wait_seconds == 0
            || profile.wait_seconds > 86400
        {
            return Err(ReceiverHold::Configuration);
        }
        anchor_custody::harden_process(profile.receiver_uid)?;
        profile
            .enrollment
            .check()
            .map_err(|_| ReceiverHold::Configuration)?;
        if crate::protected_capability_policy::Template::from_policy(
            &profile.enrollment.capability_template,
            &profile.enrollment.capability_policy_sha256,
        )
        .map_err(|_| ReceiverHold::Configuration)?
            != crate::protected_capability_policy::routing_only_v1()
        {
            return Err(ReceiverHold::Configuration);
        }
        // Claim every inherited slot before Tokio can allocate epoll/eventfd into
        // a missing descriptor number. No runtime owns any of these slots yet.
        let installation = profile
            .installation
            .verify()
            .map_err(|_| ReceiverHold::Configuration)?;
        if installation.python() != profile.python
            || installation.product_source() != profile.product_source
            || installation.purelib() != profile.purelib
            || profile.installation.index_sha256 != profile.enrollment.installation_index_sha256
            || profile
                .installation
                .source_sha256()
                .map_err(|_| ReceiverHold::Configuration)?
                != profile.enrollment.installation_source_sha256
        {
            return Err(ReceiverHold::ChangedState);
        }
        let files: [File; 15] = (4..=18)
            .map(inherited)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ReceiverHold::Configuration)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| ReceiverHold::Engine)?;
        rt.block_on(run(profile, digest(&raw), files, installation))
    })();
    result.is_ok()
}
async fn run(
    profile: Profile,
    profile_sha: String,
    files: [File; 15],
    installation: receiver_installation_verifier::reference::Verified,
) -> Result<(), ReceiverHold> {
    let enrollment_sha = profile
        .enrollment
        .canonical_sha256()
        .map_err(|_| ReceiverHold::Configuration)?;
    // Retain all custody handles through SDK shutdown, not merely through reopen.
    let [
        key_file,
        dbkey_file,
        journal_file,
        journal_dir,
        lease,
        anchor,
        anchor_dir,
        expiry,
        cache,
        producer_profile,
        archive,
        commit,
        account_dir,
        peer_file,
        original_file,
    ] = files;
    anchor_custody::check_descriptors(&anchor, &anchor_dir, &journal_dir, &account_dir)?;
    let mut key = read(&key_file, 64)?;
    let mut dbkey = read(&dbkey_file, 64)?;
    if key.len() != 32 || dbkey.len() != 32 {
        return Err(ReceiverHold::Configuration);
    }
    let keys = nostr::Keys::parse(&hex::encode(&key)).map_err(|_| ReceiverHold::Configuration)?;
    key.fill(0);
    if keys.public_key().to_hex() != profile.enrollment.account {
        return Err(ReceiverHold::ChangedState);
    }
    let dir = account_dir
        .metadata()
        .map_err(|_| ReceiverHold::Configuration)?;
    if !dir.is_dir() || dir.uid() != profile.receiver_uid || dir.mode() & 0o777 != 0o700 {
        return Err(ReceiverHold::Configuration);
    }
    let mut peer = checked_peer(peer_file, profile.consumer_uid)?;
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ReceiverHold::Configuration)?;
    let mut nonce = [0u8; 32];
    peer.read_exact(&mut nonce)
        .map_err(|_| ReceiverHold::Configuration)?;
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ReceiverHold::Configuration)?;
    let original = read(&original_file, 32768)?;
    let journal = Journal::reopen(
        OwnedFiles {
            journal: journal_file,
            journal_directory: journal_dir,
            storage_lease: lease,
            anchor,
            anchor_directory: anchor_dir,
        },
        &profile.enrollment,
    )
    .map_err(|_| ReceiverHold::Journal)?;
    let journal_sha = journal
        .fresh_source_profile_hash()
        .map_err(|_| ReceiverHold::Journal)?;
    // Fixed basename under the retained protected directory, never a packet path.
    let db_path = PathBuf::from(format!(
        "/proc/self/fd/{}/account.sqlite3",
        account_dir.as_raw_fd()
    ));
    let sqlkey = SqlCipherKey::new(hex::encode(&dbkey)).map_err(|_| ReceiverHold::Configuration)?;
    // Require an existing enrolled database. Never create a fresh account here.
    let db_fd = unsafe {
        libc::openat(
            account_dir.as_raw_fd(),
            c"account.sqlite3".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if db_fd < 0 {
        return Err(ReceiverHold::Configuration);
    }
    let db_file = unsafe { File::from_raw_fd(db_fd) };
    let db_meta = db_file
        .metadata()
        .map_err(|_| ReceiverHold::Configuration)?;
    if !db_meta.is_file()
        || db_meta.nlink() != 1
        || db_meta.uid() != profile.receiver_uid
        || db_meta.mode() & 0o777 != 0o600
    {
        return Err(ReceiverHold::Configuration);
    }
    dbkey.fill(0);
    let storage = SqliteAccountStorage::open_encrypted(&db_path, &sqlkey)
        .map_err(|_| ReceiverHold::Engine)?;
    let reopened = std::fs::metadata(&db_path).map_err(|_| ReceiverHold::ChangedState)?;
    if reopened.dev() != db_meta.dev() || reopened.ino() != db_meta.ino() {
        return Err(ReceiverHold::ChangedState);
    }
    let template = crate::protected_capability_policy::Template::from_policy(
        &profile.enrollment.capability_template,
        &profile.enrollment.capability_policy_sha256,
    )
    .map_err(|_| ReceiverHold::Configuration)?;
    let engine = owned_routed_engine(storage, keys, template)?;
    let group =
        GroupId::new(hex::decode(&profile.enrollment.group).map_err(|_| ReceiverHold::Malformed)?);
    let operators = profile
        .enrollment
        .operators
        .iter()
        .map(|s| {
            hex::decode(s)
                .map(MemberId::new)
                .map_err(|_| ReceiverHold::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let sdk = nostr_sdk::Client::builder().build();
    let relay = NostrSdkRelayClient::new(sdk.clone());
    let adapter = NostrTransportAdapter::new(Arc::new(relay.clone()));
    let relay_spool = relay_spool::anonymous(&cache)?;
    let mut factory = SemanticFactory::reopen(
        engine,
        group.clone(),
        operators,
        journal,
        adapter.clone(),
        profile.endpoints.clone(),
        reopen::ReopenFiles { expiry, cache },
    )?;
    let binding = owned_producer::GroupBinding::read(
        &factory.receiver.engine,
        &group,
        &profile.transport_group,
    )?;
    let producer = owned_producer::InstalledProducer {
        python: profile.python,
        source: profile.product_source,
        purelib: profile.purelib,
        closure: installation
            .closure()
            .map_err(|_| ReceiverHold::Configuration)?,
    };
    let ask = producer.produce(
        owned_producer::Inputs {
            profile: producer_profile,
            archive,
            commit,
        },
        &original,
        &binding,
    )?;
    // The child may have performed external reads. Revalidate the complete
    // installed inventory before publishing its retained card.
    installation
        .check()
        .map_err(|_| ReceiverHold::ChangedState)?;
    let forwarder = forward(sdk.clone(), adapter.clone(), relay_spool);
    let result = exchange(
        &mut factory,
        &adapter,
        &forwarder,
        &mut peer,
        Session {
            ask,
            transport_group: profile.transport_group,
            wait_seconds: profile.wait_seconds,
            profile_sha,
            enrollment_sha,
            journal_sha,
            installation_index_sha256: profile.enrollment.installation_index_sha256,
            installation_source_sha256: profile.enrollment.installation_source_sha256,
            capability_template: profile.enrollment.capability_template,
            capability_policy_sha256: profile.enrollment.capability_policy_sha256,
            installation: Some(installation),
            nonce,
        },
    )
    .await;
    forwarder.abort();
    let _ = forwarder.await;
    let shutdown = tokio::time::timeout(Duration::from_secs(5), sdk.shutdown()).await;
    // factory and every original custody descriptor remain alive until shutdown.
    drop(factory);
    drop((key_file, dbkey_file, account_dir, db_file, original_file));
    if shutdown.is_err() {
        return Err(ReceiverHold::Engine);
    }
    result
}

struct Session {
    ask: OriginalAsk,
    transport_group: Vec<u8>,
    wait_seconds: u32,
    profile_sha: String,
    enrollment_sha: String,
    journal_sha: String,
    installation_index_sha256: String,
    installation_source_sha256: String,
    capability_template: String,
    capability_policy_sha256: String,
    installation: Option<receiver_installation_verifier::reference::Verified>,
    nonce: [u8; 32],
}
/// Actual production activation/post/replay/consume/frame state machine.
/// Parameters are private owned objects, not an external authority DTO.
async fn exchange<S: StorageProvider + 'static>(
    factory: &mut SemanticFactory<S>,
    adapter: &NostrTransportAdapter,
    forwarder: &relay_spool::Forwarder,
    peer: &mut UnixStream,
    session: Session,
) -> Result<(), ReceiverHold> {
    let context = (
        hex::encode(session.nonce),
        session.profile_sha.clone(),
        session.enrollment_sha.clone(),
        session.journal_sha.clone(),
    );
    let result = exchange_inner(factory, adapter, forwarder, peer, session).await;
    if let Err(error) = &result {
        // Failure status has a distinct schema and confers no authority. A lost
        // error response remains held, exactly like a lost consumed response.
        let reason = match error {
            ReceiverHold::Configuration => "configuration",
            ReceiverHold::Journal => "journal",
            ReceiverHold::Capacity => "capacity",
            ReceiverHold::Latched => "latched",
            ReceiverHold::Engine => "engine_or_transport",
            ReceiverHold::ChangedState => "native_or_semantic_state",
            ReceiverHold::Malformed => "malformed",
        };
        let response = serde_json::json!({
            "schema":"heterodyne-owned-receiver-hold.v1", "nonce_hex":context.0,
            "startup_profile_sha256":context.1, "enrollment_sha256":context.2,
            "journal_profile_sha256":context.3, "reason":reason,
            "reconciliation_required":true, "automatic_replay_permitted":false,
            "native_or_external_effects_may_be_unknown":true
        });
        if let Ok(bytes) = serde_json::to_vec(&response) {
            let _ = write_frame(peer, &bytes);
        }
    }
    result
}
async fn exchange_inner<S: StorageProvider + 'static>(
    factory: &mut SemanticFactory<S>,
    adapter: &NostrTransportAdapter,
    forwarder: &relay_spool::Forwarder,
    peer: &mut UnixStream,
    session: Session,
) -> Result<(), ReceiverHold> {
    let ask = session.ask;
    owned_producer::GroupBinding::read(
        &factory.receiver.engine,
        &ask.expected_group,
        &session.transport_group,
    )?;
    if ask.expected_group != factory.receiver.group {
        return Err(ReceiverHold::ChangedState);
    }
    let ask_id = ask.ask_id.clone();
    let operation_sha = digest(&ask.operation);
    let expected_ask = serde_json::to_value(&ask).map_err(|_| ReceiverHold::Malformed)?;

    tokio::time::timeout(
        Duration::from_secs(30),
        adapter.activate_account(TransportAccountActivation {
            account_id: factory.receiver.engine.self_id(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: factory.receiver.group.clone(),
                transport_group_id: session.transport_group.clone(),
                endpoints: factory.endpoints.clone(),
            }],
            since: None,
        }),
    )
    .await
    .map_err(|_| ReceiverHold::Engine)?
    .map_err(|_| ReceiverHold::Engine)?;
    if !factory.catalog_has_ask(&ask_id)? {
        tokio::time::timeout(Duration::from_secs(30), factory.post(ask))
            .await
            .map_err(|_| ReceiverHold::Engine)??;
    }
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(u64::from(session.wait_seconds));
    let mut inspect = true;
    let mut next_inspection = tokio::time::Instant::now();
    let mut oversized = 0u64;
    loop {
        if forwarder.is_finished() {
            return Err(ReceiverHold::Engine);
        }
        // Drain every queued delivery before inspecting an approval. Coverage
        // includes every endpoint of this activation, with no history floor.
        let replay_complete = adapter
            .account_subscription_eose(&factory.receiver.engine.self_id())
            .await
            .complete();
        let idle_deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(1));
        let wait = if inspect {
            Duration::from_millis(5)
        } else {
            idle_deadline.saturating_duration_since(tokio::time::Instant::now())
        };
        match tokio::time::timeout(wait, adapter.receive()).await {
            Ok(Ok(Some(delivery))) => {
                if delivery.account_id != factory.receiver.engine.self_id() {
                    return Err(ReceiverHold::ChangedState);
                }
                match factory.ingest(delivery.message).await {
                    Ok(_) => {}
                    Err(ReceiverHold::Capacity) if !factory.held && !factory.receiver.latched => {
                        oversized = oversized.saturating_add(1);
                        tracing::debug!(target: "cgka_engine::protected_receiver", method = "exchange", oversized, "ignored pre-effect oversized relay input");
                    }
                    Err(error) => return Err(error),
                }
                inspect = true;
                if tokio::time::Instant::now() >= deadline {
                    return Err(ReceiverHold::Engine);
                }
                continue;
            }
            Ok(Ok(None)) | Ok(Err(_)) => return Err(ReceiverHold::Engine),
            Err(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ReceiverHold::Engine);
        }
        if !replay_complete
            || !forwarder.is_drained()
            || (!inspect && tokio::time::Instant::now() < next_inspection)
        {
            inspect = false;
            continue;
        }
        inspect = false;
        next_inspection = tokio::time::Instant::now() + Duration::from_secs(1);
        factory.catalog_start()?;
        factory.load_retained(&ask_id)?;
        factory.expire()?;
        let retained = factory
            .asks
            .get(&ask_id)
            .ok_or(ReceiverHold::ChangedState)?;
        let retained_original =
            serde_json::to_value(&retained.original).map_err(|_| ReceiverHold::Malformed)?;
        if retained_original != expected_ask {
            return Err(ReceiverHold::ChangedState);
        }
        if retained.conflicted || retained.expired || retained.consumed {
            return Err(ReceiverHold::ChangedState);
        }
        if retained.receipt.is_some() {
            if forwarder.is_finished() {
                return Err(ReceiverHold::Engine);
            }
            owned_producer::GroupBinding::read(
                &factory.receiver.engine,
                &factory.receiver.group,
                &session.transport_group,
            )?;
            if let Some(installation) = &session.installation {
                installation
                    .check()
                    .map_err(|_| ReceiverHold::ChangedState)?;
            }
            factory.consume(&ask_id, &operation_sha)?;
            let consumption_key = consumed_key(factory, &ask_id, &operation_sha)?;
            let receipt = factory.asks[&ask_id]
                .receipt
                .as_ref()
                .ok_or(ReceiverHold::ChangedState)?;
            // Exact consumed source result over the already authenticated peer;
            // a lost write is UNKNOWN, never unconsume or replay.
            let response = Consumed {
                schema: "heterodyne-owned-consumed.v3",
                nonce_hex: hex::encode(session.nonce),
                startup_profile_sha256: &session.profile_sha,
                enrollment_sha256: &session.enrollment_sha,
                journal_profile_sha256: &session.journal_sha,
                installation_index_sha256: &session.installation_index_sha256,
                installation_source_sha256: &session.installation_source_sha256,
                capability_template: &session.capability_template,
                capability_policy_sha256: &session.capability_policy_sha256,
                original: &retained_original,
                consumption_key,
                receipt,
            };
            let bytes = serde_json::to_vec(&response).map_err(|_| ReceiverHold::Malformed)?;
            write_frame(peer, &bytes)?;
            return Ok(());
        }
    }
}

/// Private wire, not a deserializable approval constructor. The peer owns the
/// nonce and independently compares exact retained originals and enrolled pins.
#[derive(Serialize)]
struct Consumed<'a> {
    schema: &'static str,
    nonce_hex: String,
    startup_profile_sha256: &'a str,
    enrollment_sha256: &'a str,
    journal_profile_sha256: &'a str,
    installation_index_sha256: &'a str,
    installation_source_sha256: &'a str,
    capability_template: &'a str,
    capability_policy_sha256: &'a str,
    original: &'a serde_json::Value,
    consumption_key: crate::protected_recovery::UseKey,
    receipt: &'a SemanticReceipt,
}

fn consumed_key<S: StorageProvider + 'static>(
    factory: &SemanticFactory<S>,
    ask: &str,
    operation: &str,
) -> Result<crate::protected_recovery::UseKey, ReceiverHold> {
    match &factory.receiver.journal {
        crate::protected_receiver::ReceiverJournal::Ordered(journal) => journal
            .consumed_key(ask, operation)
            .map_err(|_| ReceiverHold::ChangedState),
        _ => Err(ReceiverHold::ChangedState),
    }
}

fn write_frame(peer: &mut UnixStream, bytes: &[u8]) -> Result<(), ReceiverHold> {
    if bytes.len() > 256 * 1024 {
        return Err(ReceiverHold::Configuration);
    }
    peer.write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| peer.write_all(bytes))
        .map_err(|_| ReceiverHold::Engine)
}
#[path = "protected_owned_relay.rs"]
mod relay_spool;
fn forward(
    sdk: nostr_sdk::Client,
    adapter: NostrTransportAdapter,
    spool: File,
) -> relay_spool::Forwarder {
    forward_notifications(sdk.notifications(), adapter, spool)
}
fn forward_notifications(
    notifications: tokio::sync::broadcast::Receiver<nostr_sdk::RelayPoolNotification>,
    adapter: NostrTransportAdapter,
    spool: File,
) -> relay_spool::Forwarder {
    relay_spool::forward(notifications, adapter, spool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::MessageStorage;
    #[tokio::test]
    async fn real_native_consumed_receipt_frames_exact_original_and_nonce() {
        let (mut factory, mut operator, _, _) = super::super::tests::fixture().await;
        let root = tempfile::tempdir().unwrap();
        let (journal, _) = crate::protected_receiver::tests::ordered_fixture(
            root.path(),
            &factory.receiver.engine,
            &factory.receiver.group,
            &factory.receiver.operators,
        );
        factory.receiver.journal = crate::protected_receiver::ReceiverJournal::Ordered(journal);
        super::super::tests::approve(&mut factory, &mut operator, "ask3").await;
        let original = serde_json::to_value(&factory.asks["ask3"].original).unwrap();
        let expected_operator = operator.self_id();
        let (mut receiver, mut consumer) = UnixStream::pair().unwrap();
        let nonce = [0x57u8; 32];
        consumer.write_all(&nonce).unwrap();
        let mut challenge = [0u8; 32];
        receiver.read_exact(&mut challenge).unwrap();
        let operation = digest(b"exact source-only operation");
        assert!(consumed_key(&factory, "ask3", &operation).is_err());
        factory.consume("ask3", &operation).unwrap();
        let consumption_key = consumed_key(&factory, "ask3", &operation).unwrap();
        assert!(consumed_key(&factory, "ask3", &"ff".repeat(32)).is_err());
        let receipt = factory.asks["ask3"].receipt.as_ref().unwrap();
        let response = Consumed {
            schema: "heterodyne-owned-consumed.v3",
            nonce_hex: hex::encode(challenge),
            startup_profile_sha256: &"00".repeat(32),
            enrollment_sha256: &"01".repeat(32),
            journal_profile_sha256: &"02".repeat(32),
            installation_index_sha256: &"03".repeat(32),
            installation_source_sha256: &"04".repeat(32),
            capability_template: "routing-only-v1",
            capability_policy_sha256: &crate::protected_capability_policy::routing_only_v1()
                .policy_sha256(),
            original: &original,
            consumption_key,
            receipt,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        write_frame(&mut receiver, &bytes).unwrap();
        let mut length = [0; 4];
        consumer.read_exact(&mut length).unwrap();
        assert_eq!(u32::from_be_bytes(length) as usize, bytes.len());
        let mut actual = vec![0; bytes.len()];
        consumer.read_exact(&mut actual).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&actual).unwrap();
        assert_eq!(value["nonce_hex"], hex::encode(nonce));
        assert_eq!(value["original"], original);
        let records: Vec<serde_json::Value> =
            std::fs::read_to_string(root.path().join("receiver/journal"))
                .unwrap()
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
        let card = records
            .iter()
            .find(|r| r["body"]["kind"] == "card-complete")
            .unwrap();
        let consumed = records
            .iter()
            .find(|r| r["body"]["kind"] == "consumed")
            .unwrap();
        assert_eq!(value["consumption_key"], consumed["body"]["key"]);
        assert_eq!(
            value["consumption_key"]["header_sha256"],
            records[0]["sha256"]
        );
        assert_eq!(
            value["consumption_key"]["card_complete_sequence"],
            card["sequence"]
        );
        assert_eq!(value["consumption_key"]["ask_id"], "ask3");
        assert_eq!(
            value["consumption_key"]["original_operation_sha256"],
            operation
        );

        assert_eq!(value["receipt"]["decision"], "Approve");
        assert_eq!(
            value["receipt"]["operator"],
            serde_json::to_value(expected_operator).unwrap()
        );
        assert_eq!(
            value["receipt"]["operation_sha256"],
            digest(b"exact source-only operation")
        );
        assert!(
            factory
                .consume("ask3", &digest(b"exact source-only operation"))
                .is_err()
        );
        drop(consumer);
        assert!(write_frame(&mut receiver, &bytes).is_err());
        // Lost-return/write does not undo the durable native one-use consumption.
        assert!(factory.asks["ask3"].consumed);
    }
    #[test]
    fn actual_kernel_peer_identity_and_socket_kind_are_required() {
        use std::os::fd::IntoRawFd;
        let (writer, _reader) = UnixStream::pair().unwrap();
        let file = unsafe { File::from_raw_fd(writer.into_raw_fd()) };
        assert!(checked_peer(file, unsafe { libc::geteuid() }).is_ok());
        let (writer, _reader) = UnixStream::pair().unwrap();
        let file = unsafe { File::from_raw_fd(writer.into_raw_fd()) };
        assert!(checked_peer(file, unsafe { libc::geteuid() }.wrapping_add(1)).is_err());
        let (writer, _reader) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let file = unsafe { File::from_raw_fd(writer.into_raw_fd()) };
        assert!(checked_peer(file, unsafe { libc::geteuid() }).is_err());
    }
    fn session(ask: OriginalAsk) -> Session {
        Session {
            ask,
            transport_group: vec![7; 32],
            wait_seconds: 2,
            profile_sha: "00".repeat(32),
            enrollment_sha: "01".repeat(32),
            journal_sha: "02".repeat(32),
            installation_index_sha256: "04".repeat(32),
            installation_source_sha256: "05".repeat(32),
            capability_template: crate::protected_capability_policy::routing_only_v1()
                .id()
                .into(),
            capability_policy_sha256: crate::protected_capability_policy::routing_only_v1()
                .policy_sha256(),
            installation: None,
            nonce: [0x61; 32],
        }
    }
    fn notification(event: nostr::Event) -> nostr_sdk::RelayPoolNotification {
        nostr_sdk::RelayPoolNotification::Event {
            relay_url: "wss://semantic.invalid".parse().unwrap(),
            subscription_id: nostr::SubscriptionId::new("fixture"),
            event: Box::new(event),
        }
    }
    #[tokio::test]
    async fn owned_exchange_ignores_invalid_replay_and_oversize_then_consumes_after_eose() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        use nostr::{EventBuilder, Kind, Tag, TagKind};
        let (mut factory, mut operator, root, relay) =
            super::super::tests::finite_fixture_lifetime(60_000).await;
        factory
            .enable_catalog(super::super::tests::cache(root.path(), "owner-cache"))
            .unwrap();
        let ask = super::super::tests::finite_original("ask3", &factory.receiver.group);
        factory.post(ask.clone()).await.unwrap();
        let target = factory.asks["ask3"].app_ids[0].clone();
        let approval = super::super::tests::reaction(&mut operator, &factory, &target, "👍").await;
        let approval: nostr::Event = serde_json::from_slice(&approval.payload).unwrap();
        let before = relay.wires.lock().unwrap().len();
        let subscriptions_before = relay.subscriptions.lock().unwrap().len();
        let adapter = factory.transport.clone();
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let forwarder = forward_notifications(rx, adapter.clone(), tempfile::tempfile().unwrap());
        let (mut receiver, mut consumer) = UnixStream::pair().unwrap();
        let mut before_eose = consumer.try_clone().unwrap();
        let keepalive = tx.clone();
        let driver = tokio::spawn(async move {
            loop {
                let subscriptions = relay.subscriptions.lock().unwrap().clone();
                if subscriptions.len() > subscriptions_before {
                    let outsider = nostr::Keys::generate();
                    let h = || Tag::custom(TagKind::custom("h"), [hex::encode([7; 32])]);
                    let malformed = EventBuilder::new(Kind::MlsGroupMessage, "invalid")
                        .tags([h(), Tag::custom(TagKind::custom("extra"), ["x"])])
                        .sign_with_keys(&outsider)
                        .unwrap();
                    tx.send(notification(malformed)).unwrap();
                    let oversized =
                        EventBuilder::new(Kind::MlsGroupMessage, "A".repeat(1024 * 1024 + 1))
                            .tags([h()])
                            .sign_with_keys(&outsider)
                            .unwrap();
                    tx.send(notification(oversized)).unwrap();
                    tx.send(notification(approval)).unwrap();
                    // Do not let the genuine queued receipt bypass initial replay coverage.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    before_eose.set_nonblocking(true).unwrap();
                    assert_eq!(
                        before_eose.read(&mut [0]).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                    before_eose.set_nonblocking(false).unwrap();
                    for subscription in subscriptions {
                        tx.send(nostr_sdk::RelayPoolNotification::Message {
                            relay_url: "wss://semantic.invalid".parse().unwrap(),
                            message: nostr::RelayMessage::EndOfStoredEvents(
                                std::borrow::Cow::Owned(nostr::SubscriptionId::new(
                                    subscription.subscription_id(),
                                )),
                            ),
                        })
                        .unwrap();
                    }
                    return relay.wires.lock().unwrap().len();
                }
                tokio::task::yield_now().await;
            }
        });
        exchange(
            &mut factory,
            &adapter,
            &forwarder,
            &mut receiver,
            session(ask),
        )
        .await
        .unwrap();
        factory.load_retained("ask3").unwrap();
        assert!(factory.asks["ask3"].consumed);
        let mut size = [0; 4];
        consumer.read_exact(&mut size).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
        consumer.read_exact(&mut bytes).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["receipt"]["decision"], "Approve");
        assert_eq!(response["consumption_key"]["ask_id"], "ask3");
        assert!(!forwarder.is_finished());
        // Existing retained card was not republished by the actual exchange path.
        assert_eq!(before, 2);
        assert_eq!(driver.await.unwrap(), before);
        drop(keepalive);
        forwarder.abort();
    }

    #[tokio::test]
    async fn owned_exchange_posts_once_but_no_eose_or_dead_forwarder_never_consumes() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        for closed in [false, true] {
            let (mut factory, _, root, relay) =
                super::super::tests::finite_fixture_lifetime(60_000).await;
            factory
                .enable_catalog(super::super::tests::cache(root.path(), "owner-cache"))
                .unwrap();
            let ask = super::super::tests::finite_original("ask3", &factory.receiver.group);
            let adapter = factory.transport.clone();
            let (tx, rx) = tokio::sync::broadcast::channel(2);
            let forwarder =
                forward_notifications(rx, adapter.clone(), tempfile::tempfile().unwrap());
            if closed {
                drop(tx);
                tokio::task::yield_now().await;
            }
            let (mut receiver, mut consumer) = UnixStream::pair().unwrap();
            assert!(
                exchange(
                    &mut factory,
                    &adapter,
                    &forwarder,
                    &mut receiver,
                    session(ask)
                )
                .await
                .is_err()
            );
            assert!(!factory.asks["ask3"].consumed);
            assert_eq!(relay.wires.lock().unwrap().len(), 2);
            let mut length = [0; 4];
            consumer.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
            consumer.read_exact(&mut bytes).unwrap();
            let hold: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(hold["schema"], "heterodyne-owned-receiver-hold.v1");
            assert_eq!(hold["nonce_hex"], hex::encode([0x61; 32]));
            assert_eq!(hold["automatic_replay_permitted"], false);
            assert_eq!(hold["reconciliation_required"], true);
            forwarder.abort();
        }
    }
    #[tokio::test]
    async fn genuine_route_undecryptable_wire_retains_unknown_and_reports_hold_without_replay() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        use nostr::{EventBuilder, Kind, Tag, TagKind};
        let (mut factory, mut operator, root, relay) =
            super::super::tests::finite_fixture_lifetime(60_000).await;
        factory
            .enable_catalog(super::super::tests::cache(root.path(), "unknown-cache"))
            .unwrap();
        let ask = super::super::tests::finite_original("ask3", &factory.receiver.group);
        factory.post(ask.clone()).await.unwrap();
        let target = factory.asks["ask3"].app_ids[0].clone();
        let actual = super::super::tests::reaction(&mut operator, &factory, &target, "👍").await;
        let actual: serde_json::Value = serde_json::from_slice(&actual.payload).unwrap();
        let h = actual["tags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t[0] == "h")
            .unwrap()[1]
            .as_str()
            .unwrap();
        let cipher = EventBuilder::new(
            Kind::MlsGroupMessage,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .tags([Tag::custom(TagKind::custom("h"), [h])])
        .sign_with_keys(&nostr::Keys::generate())
        .unwrap();
        let wire = transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&cipher)
            .unwrap()
            .to_transport_message()
            .unwrap();
        let adapter = factory.transport.clone();
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let forwarder = forward_notifications(rx, adapter.clone(), tempfile::tempfile().unwrap());
        let keepalive = tx.clone();
        let driver = tokio::spawn(async move {
            while relay.subscriptions.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
            tx.send(notification(cipher)).unwrap();
        });
        let (mut receiver, mut consumer) = UnixStream::pair().unwrap();
        assert_eq!(
            exchange(
                &mut factory,
                &adapter,
                &forwarder,
                &mut receiver,
                session(ask)
            )
            .await,
            Err(ReceiverHold::ChangedState)
        );
        driver.await.unwrap();
        let mut length = [0; 4];
        consumer.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        consumer.read_exact(&mut bytes).unwrap();
        let hold: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(hold["schema"], "heterodyne-owned-receiver-hold.v1");
        assert_eq!(hold["nonce_hex"], hex::encode([0x61; 32]));
        assert_eq!(hold["reason"], "native_or_semantic_state");
        assert_eq!(hold["automatic_replay_permitted"], false);
        assert_eq!(hold["reconciliation_required"], true);
        assert!(hold.get("receipt").is_none());
        assert_eq!(
            factory
                .receiver
                .engine
                .storage
                .get_message(&wire.id)
                .unwrap()
                .state,
            cgka_traits::message::MessageState::PeelDeferred
        );
        let before = factory.receiver.journal.length().unwrap();
        assert!(factory.held && factory.receiver.latched);
        assert!(factory.ingest(wire.clone()).await.is_err());
        assert_eq!(factory.receiver.journal.length().unwrap(), before);
        assert_eq!(
            factory
                .receiver
                .engine
                .storage
                .get_message(&wire.id)
                .unwrap()
                .state,
            cgka_traits::message::MessageState::PeelDeferred
        );
        assert!(!factory.asks["ask3"].consumed);
        drop(keepalive);
        forwarder.abort();
    }
    #[tokio::test]
    async fn owned_notification_lag_and_shutdown_end_forwarder() {
        for lag in [false, true] {
            let (factory, _, _, _) = super::super::tests::fixture().await;
            let (tx, rx) = tokio::sync::broadcast::channel(1);
            let forwarder =
                forward_notifications(rx, factory.transport.clone(), tempfile::tempfile().unwrap());
            for _ in 0..if lag { 3 } else { 1 } {
                tx.send(nostr_sdk::RelayPoolNotification::Shutdown).unwrap();
            }
            tokio::time::timeout(Duration::from_secs(1), forwarder)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn frame_limit_refuses_without_any_peer_bytes() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        assert!(write_frame(&mut writer, &vec![0; 256 * 1024 + 1]).is_err());
        assert_eq!(
            reader.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

fn checked_peer(peer_file: File, consumer_uid: u32) -> Result<UnixStream, ReceiverHold> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            peer_file.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of::<libc::ucred>()
        || credentials.uid != consumer_uid
    {
        return Err(ReceiverHold::Configuration);
    }
    let mut socket_type: libc::c_int = 0;
    let mut type_size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            peer_file.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut type_size,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err(ReceiverHold::Configuration);
    }
    let mut domain: libc::c_int = 0;
    let mut domain_size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            peer_file.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut domain as *mut libc::c_int).cast(),
            &mut domain_size,
        )
    } != 0
        || domain != libc::AF_UNIX
    {
        return Err(ReceiverHold::Configuration);
    }
    let peer = UnixStream::from(OwnedFd::from(peer_file));
    peer.peer_addr().map_err(|_| ReceiverHold::Configuration)?;
    Ok(peer)
}

#[path = "protected_owned_enroll.rs"]
mod enroll;
pub(crate) fn enroll_entry() -> bool {
    enroll::entry()
}

#[cfg(test)]
#[path = "protected_whole_packet_tests.rs"]
mod whole_packet_qualification;

#[cfg(test)]
#[path = "protected_capability_policy_tests.rs"]
mod capability_tests;
