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
    producer_closure: Vec<(PathBuf, String)>,
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
    let m = file.metadata().map_err(|_| ReceiverHold::Configuration)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o777 != 0o400
        || m.len() == 0
        || m.len() > limit
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(ReceiverHold::Configuration);
    }
    let mut raw = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|_| ReceiverHold::Configuration)?;
    if raw.len() as u64 != m.len() {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(raw)
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
        if profile.schema != "heterodyne-protected-receiver-process.v1"
            || profile.receiver_uid != unsafe { libc::geteuid() }
            || profile.wait_seconds == 0
            || profile.wait_seconds > 86400
        {
            return Err(ReceiverHold::Configuration);
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| ReceiverHold::Engine)?;
        rt.block_on(run(profile, digest(&raw)))
    })();
    result.is_ok()
}
async fn run(profile: Profile, profile_sha: String) -> Result<(), ReceiverHold> {
    let enrollment_sha =
        digest(&serde_json::to_vec(&profile.enrollment).map_err(|_| ReceiverHold::Malformed)?);
    let closure_sha = digest(
        &serde_json::to_vec(&profile.producer_closure).map_err(|_| ReceiverHold::Malformed)?,
    );
    // Retain all custody handles through SDK shutdown, not merely through reopen.
    let key_file = inherited(4)?;
    let dbkey_file = inherited(5)?;
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
    let journal_file = inherited(6)?;
    let journal_dir = inherited(7)?;
    let lease = inherited(8)?;
    let anchor = inherited(9)?;
    let anchor_dir = inherited(10)?;
    let expiry = inherited(11)?;
    let cache = inherited(12)?;
    let producer_profile = inherited(13)?;
    let archive = inherited(14)?;
    let commit = inherited(15)?;
    let account_dir = inherited(16)?;
    let peer_file = inherited(17)?;
    let original_file = inherited(18)?;
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
    let journal_sha = journal.profile_hash().map_err(|_| ReceiverHold::Journal)?;
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
    let storage =
        SqliteAccountStorage::open_encrypted(db_path, &sqlkey).map_err(|_| ReceiverHold::Engine)?;
    let engine = EngineBuilder::new(storage)
        .identity(keys.public_key().to_bytes().to_vec())
        .account_identity_proof_signer(Arc::new(Signer(keys.clone())))
        .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(keys)))
        .build()
        .map_err(|_| ReceiverHold::Engine)?;
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
    let mut factory = SemanticFactory::reopen(
        engine,
        group.clone(),
        operators,
        journal,
        adapter.clone(),
        profile.endpoints.clone(),
        reopen::ReopenFiles { expiry, cache },
    )?;
    let producer = owned_producer::InstalledProducer {
        python: profile.python,
        source: profile.product_source,
        purelib: profile.purelib,
        closure: profile.producer_closure,
    };
    let ask = producer.produce(
        owned_producer::Inputs {
            profile: producer_profile,
            archive,
            commit,
        },
        &original,
        &group,
    )?;
    let ask_id = ask.ask_id.clone();
    let operation_sha = digest(&original);
    let expected_ask = serde_json::to_value(&ask).map_err(|_| ReceiverHold::Malformed)?;
    // Own the actual SDK notification receiver. Lag/error ends this task and
    // prevents consumption; the generic application forwarder discards that error.
    let forwarder = forward(sdk.clone(), adapter.clone());
    let result = async {
        tokio::time::timeout(
            Duration::from_secs(30),
            adapter.activate_account(TransportAccountActivation {
                account_id: factory.receiver.engine.self_id(),
                inbox_endpoints: profile.endpoints.clone(),
                group_subscriptions: vec![TransportGroupSubscription {
                    group_id: group,
                    transport_group_id: profile.transport_group,
                    endpoints: profile.endpoints,
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
            tokio::time::Instant::now() + Duration::from_secs(u64::from(profile.wait_seconds));
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
            match tokio::time::timeout(Duration::from_millis(5), adapter.receive()).await {
                Ok(Ok(Some(delivery))) => {
                    if delivery.account_id != factory.receiver.engine.self_id() {
                        return Err(ReceiverHold::ChangedState);
                    }
                    factory.ingest(delivery.message).await?;
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
            if !replay_complete {
                continue;
            }
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
                let receipt = factory.consume(&ask_id, &operation_sha)?;
                // Exact consumed source result over the already authenticated peer;
                // a lost write is UNKNOWN, never unconsume or replay.
                let response = Consumed {
                    schema: "heterodyne-owned-consumed.v1",
                    nonce_hex: hex::encode(nonce),
                    startup_profile_sha256: &profile_sha,
                    enrollment_sha256: &enrollment_sha,
                    journal_profile_sha256: &journal_sha,
                    producer_closure_sha256: &closure_sha,
                    original: &retained_original,
                    receipt,
                };
                let bytes = serde_json::to_vec(&response).map_err(|_| ReceiverHold::Malformed)?;
                write_frame(&mut peer, &bytes)?;
                return Ok(());
            }
        }
    }
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

/// Private wire, not a deserializable approval constructor. The peer owns the
/// nonce and independently compares exact retained originals and enrolled pins.
#[derive(Serialize)]
struct Consumed<'a> {
    schema: &'static str,
    nonce_hex: String,
    startup_profile_sha256: &'a str,
    enrollment_sha256: &'a str,
    journal_profile_sha256: &'a str,
    producer_closure_sha256: &'a str,
    original: &'a serde_json::Value,
    receipt: &'a SemanticReceipt,
}

fn write_frame(peer: &mut UnixStream, bytes: &[u8]) -> Result<(), ReceiverHold> {
    if bytes.len() > 256 * 1024 {
        return Err(ReceiverHold::Configuration);
    }
    peer.write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| peer.write_all(bytes))
        .map_err(|_| ReceiverHold::Engine)
}
fn forward(sdk: nostr_sdk::Client, adapter: NostrTransportAdapter) -> tokio::task::JoinHandle<()> {
    let mut notifications = sdk.notifications();
    tokio::spawn(async move {
        while let Ok(notification) = notifications.recv().await {
            match notification {
                nostr_sdk::RelayPoolNotification::Event {
                    relay_url,
                    subscription_id,
                    event,
                } => {
                    let Ok(event) =
                        transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&event)
                    else {
                        break;
                    };
                    if adapter
                        .handle_relay_event(transport_nostr_adapter::NostrRelayEvent {
                            endpoint: TransportEndpoint(relay_url.to_string()),
                            subscription_id: Some(subscription_id.to_string()),
                            event,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                nostr_sdk::RelayPoolNotification::Message {
                    relay_url,
                    message: nostr::RelayMessage::EndOfStoredEvents(subscription_id),
                } => {
                    adapter
                        .handle_relay_eose(
                            TransportEndpoint(relay_url.to_string()),
                            subscription_id.to_string(),
                        )
                        .await;
                }
                nostr_sdk::RelayPoolNotification::Shutdown => break,
                _ => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn real_native_consumed_receipt_frames_exact_original_and_nonce() {
        let (mut factory, mut operator, _, _) = super::super::tests::fixture().await;
        super::super::tests::approve(&mut factory, &mut operator, "ask3").await;
        let original = serde_json::to_value(&factory.asks["ask3"].original).unwrap();
        let expected_operator = operator.self_id();
        let (mut receiver, mut consumer) = UnixStream::pair().unwrap();
        let nonce = [0x57u8; 32];
        consumer.write_all(&nonce).unwrap();
        let mut challenge = [0u8; 32];
        receiver.read_exact(&mut challenge).unwrap();
        let receipt = factory
            .consume("ask3", &digest(b"exact source-only operation"))
            .unwrap();
        let response = Consumed {
            schema: "heterodyne-owned-consumed.v1",
            nonce_hex: hex::encode(challenge),
            startup_profile_sha256: &"00".repeat(32),
            enrollment_sha256: &"01".repeat(32),
            journal_profile_sha256: &"02".repeat(32),
            producer_closure_sha256: &"03".repeat(32),
            original: &original,
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
