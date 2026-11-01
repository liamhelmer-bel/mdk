//! Fixed inherited-descriptor initializer entry. Root only validates custody
//! and drops privilege; all key/database work runs as the receiver identity.
use crate::{
    generation::Generation,
    initializer::{Artifact, Ledger},
    initializer_handoff::{self, Facts},
    preparation,
    publication_journal::JournaledRelay,
};
use cgka_traits::TransportEndpoint;
use receiver_installation_verifier::reference::Installation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};

type Result<T> = std::result::Result<T, ()>;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: String,
    request_sha256: String,
    storage_generation: String,
    receiver_uid: u32,
    consumer_uid: u32,
    group: String,
    operators: Vec<String>,
    inbox_endpoints: Vec<String>,
    key_package_endpoints: Vec<String>,
    minimum_accepted_endpoints: usize,
    deadline_unix_ms: u64,
    wait_seconds: u64,
    expiry_profile_sha256: String,
    installation: Installation,
    capability_template: String,
    capability_policy_sha256: String,
}
fn hash(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_millis()
        .try_into()
        .map_err(|_| ())?)
}
fn protected_bytes(file: &File) -> Result<Vec<u8>> {
    let m = file.metadata().map_err(|_| ())?;
    let f = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.mode() & 0o7777 != 0o400
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > 65536
        || f < 0
        || f & (libc::O_PATH | libc::O_APPEND) != 0
        || f & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(());
    }
    let mut raw = vec![0; m.len() as usize];
    std::os::unix::fs::FileExt::read_exact_at(file, &mut raw, 0).map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(());
    }
    Ok(raw)
}
fn endpoints(values: &[String]) -> Result<()> {
    if values.is_empty() || values.len() > 16 {
        return Err(());
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if value.len() > 2048
            || !value.starts_with("wss://")
            || nostr::RelayUrl::parse(value).is_err()
            || !seen.insert(value)
        {
            return Err(());
        }
    }
    Ok(())
}
fn profile(raw: &[u8]) -> Result<Profile> {
    let value =
        receiver_installation_verifier::installation::parse_canonical(raw).map_err(|_| ())?;
    let p: Profile = serde_json::from_value(value).map_err(|_| ())?;
    let current = now()?;
    if p.schema != "heterodyne-protected-receiver-initializer.v2"
        || !hash(&p.request_sha256, 64)
        || !hash(&p.storage_generation, 64)
        || p.receiver_uid == 0
        || p.consumer_uid == 0
        || p.consumer_uid == p.receiver_uid
        || !hash(&p.group, 32)
        || p.operators.is_empty()
        || p.operators.len() > 64
        || p.operators.iter().any(|o| !hash(o, 64))
        || p.operators.windows(2).any(|w| w[0] >= w[1])
        || !(1..=300).contains(&p.wait_seconds)
        || p.deadline_unix_ms <= current
        || p.deadline_unix_ms - current > 600000
        || !hash(&p.expiry_profile_sha256, 64)
        || p.minimum_accepted_endpoints == 0
        || p.minimum_accepted_endpoints > p.inbox_endpoints.len().min(p.key_package_endpoints.len())
    {
        return Err(());
    }
    endpoints(&p.inbox_endpoints)?;
    endpoints(&p.key_package_endpoints)?;
    Ok(p)
}
fn drop_privilege(uid: u32, parent: &File, ledger: &File) -> Result<()> {
    let a = parent.metadata().map_err(|_| ())?;
    let b = ledger.metadata().map_err(|_| ())?;
    if !a.is_dir()
        || a.uid() != uid
        || a.gid() != uid
        || a.mode() & 0o7777 != 0o700
        || !b.is_file()
        || b.uid() != uid
        || b.gid() != uid
        || b.mode() & 0o7777 != 0o600
        || b.nlink() != 1
        || b.len() != 0
        || a.dev() != b.dev()
    {
        return Err(());
    }
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(uid, uid, uid) != 0
            || libc::setresuid(uid, uid, uid) != 0
            || libc::getuid() != uid
            || libc::geteuid() != uid
            || libc::getgid() != uid
            || libc::getegid() != uid
            || libc::getgroups(0, std::ptr::null_mut()) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
            || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
        {
            return Err(());
        }
        let mut poll = libc::pollfd {
            fd: 9,
            events: libc::POLLIN,
            revents: 0,
        };
        if libc::poll(&mut poll, 1, 0) != 0 {
            return Err(());
        }
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
            return Err(());
        }
    }
    Ok(())
}

/// Only the fixed binary invokes this function; inherited root protected pins
/// and owned namespace are mandatory. An arbitrary request body is not entry.
pub(crate) fn entry() -> Result<()> {
    if unsafe { libc::geteuid() } != 0
        || unsafe { libc::getpid() } != 1
        || std::env::args_os().count() != 1
        || std::env::vars_os().next().is_some()
    {
        return Err(());
    }
    // Unique descriptor ownership, with no opening of account/private state.
    let [original, parent, ledger, lease, expiry, channel] =
        [3, 4, 5, 6, 7, 8].map(|fd| unsafe { File::from_raw_fd(fd) });
    let raw = protected_bytes(&original)?;
    let p = profile(&raw)?;
    let selected = cgka_engine::protected_capability_policy::Template::from_policy(
        &p.capability_template,
        &p.capability_policy_sha256,
    )
    .map_err(|_| ())?;
    // Bounded QUIC support is not qualified by schema selection alone.
    if selected.id() != "routing-only-v1" {
        return Err(());
    }
    cgka_engine::protected_expiry_policy::verify_descriptor(&expiry, &p.expiry_profile_sha256)
        .map_err(|_| ())?;
    let installed = p.installation.verify().map_err(|_| ())?;
    let lease_meta = lease.metadata().map_err(|_| ())?;
    if !lease_meta.is_file()
        || lease_meta.uid() != 0
        || lease_meta.gid() != 0
        || lease_meta.mode() & 0o7777 != 0o600
        || lease_meta.nlink() != 1
    {
        return Err(());
    }
    drop_privilege(p.receiver_uid, &parent, &ledger)?;
    let mut record = Ledger::create(
        ledger,
        parent.try_clone().map_err(|_| ())?,
        &p.request_sha256,
        &p.storage_generation,
    )
    .map_err(|_| ())?;
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| ())?;
    let slot = hex::encode(random);
    record.material(slot.clone()).map_err(|_| ())?;
    let generation = Generation::create(&parent, &p.storage_generation).map_err(|_| ())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    let duration = Duration::from_millis(
        (p.deadline_unix_ms.saturating_sub(now()?)).min(p.wait_seconds * 1000),
    );
    let result = runtime.block_on(async {
        tokio::time::timeout(duration, async {
            let (database, keys, key) = generation.native_inputs().map_err(|_| ())?;
            let kp = p
                .key_package_endpoints
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect::<Vec<_>>();
            let inbox = p
                .inbox_endpoints
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect::<Vec<_>>();
            let prepared = preparation::prepare(&database, &key, keys.clone(), &slot, kp.clone())
                .await
                .map_err(|_| ())?;
            selected
                .validate_metadata(&prepared.metadata)
                .map_err(|_| ())?;
            if p.operators.contains(&keys.public_key().to_hex()) {
                return Err(());
            }
            let lists = preparation::relay_lists(
                &keys,
                prepared.artifact.created_at,
                kp.clone(),
                inbox.clone(),
            )
            .map_err(|_| ())?;
            let exact = [&lists[0], &lists[1], &prepared.artifact];
            let bindings = exact
                .iter()
                .zip([10002, 10050, 30443])
                .map(|(a, kind)| Artifact {
                    kind,
                    event_id: hex::encode(a.id.as_slice()),
                    sha256: hex::encode(Sha256::digest(&a.bytes)),
                    targets: if kind == 10050 {
                        p.inbox_endpoints.clone()
                    } else {
                        p.key_package_endpoints.clone()
                    },
                    required_acks: p.minimum_accepted_endpoints,
                })
                .collect::<Vec<_>>();
            let retained = generation
                .retain_publications(exact, &bindings)
                .map_err(|_| ())?;
            record.prepared(bindings.clone()).map_err(|_| ())?;
            // Final protected-input check before the first external exposure.
            if protected_bytes(&original)? != raw || now()? >= p.deadline_unix_ms {
                return Err(());
            }
            installed.check().map_err(|_| ())?;
            cgka_engine::protected_expiry_policy::verify_descriptor(
                &expiry,
                &p.expiry_profile_sha256,
            )
            .map_err(|_| ())?;
            record.exposure_begun().map_err(|_| ())?;
            let sdk = Arc::new(NostrSdkRelayClient::new(
                nostr_sdk::Client::builder().build(),
            ));
            let relay = Arc::new(
                JournaledRelay::new(record, &generation, &retained, sdk, Duration::from_secs(25))
                    .map_err(|_| ())?,
            );
            for (i, list) in lists.iter().enumerate() {
                let event = serde_json::from_slice(&list.bytes).map_err(|_| ())?;
                let targets = if i == 1 { &inbox } else { &kp };
                let outcome = relay
                    .publish_event(targets, &event, p.minimum_accepted_endpoints)
                    .await
                    .map_err(|_| ())?;
                if outcome.accepted.len() < p.minimum_accepted_endpoints {
                    return Err(());
                }
            }
            let publisher = preparation::ExactPublisher::new(
                prepared.clone(),
                relay.clone(),
                p.minimum_accepted_endpoints,
                Duration::from_secs(25),
            )
            .map_err(|_| ())?;
            preparation::publish_pending(&database, &key, &keys, publisher)
                .await
                .map_err(|_| ())?;
            relay.published(&generation).await.map_err(|_| ())?;
            let facts = Facts {
                schema: "heterodyne-owned-initialization.v1".into(),
                request_sha256: p.request_sha256.clone(),
                storage_generation: p.storage_generation.clone(),
                initializer_profile_sha256: hex::encode(Sha256::digest(&raw)),
                expiry_profile_sha256: p.expiry_profile_sha256.clone(),
                installation_index_sha256: p.installation.index_sha256.clone(),
                account: keys.public_key().to_hex(),
                key_package_ref: prepared.metadata.key_package_ref_hex,
                capability_template: p.capability_template.clone(),
                capability_policy_sha256: p.capability_policy_sha256.clone(),
            };
            initializer_handoff::send(
                &channel,
                &facts,
                &generation.handoff_descriptors().map_err(|_| ())?,
            )
            .map_err(|_| ())?;
            Ok(())
        })
        .await
        .map_err(|_| ())?
    });
    // The original bootstrap lifetime lease stays open until all native and SDK
    // objects/runtime threads have stopped and the namespace init exits.
    drop(runtime);
    drop(generation);
    drop(lease);
    result
}
