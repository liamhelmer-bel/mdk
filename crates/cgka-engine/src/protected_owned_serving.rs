//! One-engine, fixed-group conversation channel. Projections are never approval
//! receipts; every inbound event first traverses the protected semantic journal.
use super::*;
use serde_json::{Value, json};
use std::os::unix::net::UnixListener;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
#[path = "protected_serving_channel.rs"]
mod channel;
#[path = "protected_serving_projection.rs"]
mod projection;
#[path = "protected_serving_store.rs"]
mod store;
const PROTOCOL: &str = "marmot.agent-control.v2";
const MAX_FRAME: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServingProfile {
    schema: String,
    receiver_uid: u32,
    hermes_uid: u32,
    serving_generation: String,
    enrollment: Enrollment,
    endpoints: Vec<TransportEndpoint>,
    transport_group: Vec<u8>,
    installation: receiver_installation_verifier::reference::Installation,
}
struct Call {
    request: Value,
    reply: mpsc::SyncSender<Result<Value, ReceiverHold>>,
}
// Cursor requests never arrive from the socket. Each connection owns its own
// replay progress; reconnect starts from zero and Hermes deduplicates durably.
enum Command {
    Call(Call),
    Replay {
        after: u64,
        reply: mpsc::SyncSender<Result<(Vec<Value>, u64), ReceiverHold>>,
    },
}
fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(super) fn run_entry(profile_file: File, raw: &[u8]) -> Result<(), ReceiverHold> {
    let profile: ServingProfile =
        serde_json::from_slice(raw).map_err(|_| ReceiverHold::Malformed)?;
    if profile.schema != "heterodyne-protected-receiver-serving.v1"
        || profile.receiver_uid != unsafe { libc::geteuid() }
        || profile.hermes_uid == 0
        || profile.hermes_uid == profile.receiver_uid
        || !hex64(&profile.serving_generation)
        || profile.endpoints.is_empty()
        || profile.endpoints.len() > 16
        || profile.endpoints.iter().collect::<BTreeSet<_>>().len() != profile.endpoints.len()
    {
        return Err(ReceiverHold::Configuration);
    }
    anchor_custody::harden_process(profile.receiver_uid)?;
    profile
        .enrollment
        .check()
        .map_err(|_| ReceiverHold::Configuration)?;
    let template = crate::protected_capability_policy::Template::from_policy(
        &profile.enrollment.capability_template,
        &profile.enrollment.capability_policy_sha256,
    )
    .map_err(|_| ReceiverHold::Configuration)?;
    if template != crate::protected_capability_policy::admind_receiver_v1()
        && template != crate::protected_capability_policy::routing_only_v1()
    {
        return Err(ReceiverHold::Configuration);
    }
    // Claim slots BEFORE Tokio can allocate into an absent inherited slot.
    let files: [File; 13] = (4..=16)
        .map(inherited)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| ReceiverHold::Configuration)?;
    let installation = profile
        .installation
        .verify()
        .map_err(|_| ReceiverHold::Configuration)?;
    if profile.installation.index_sha256 != profile.enrollment.installation_index_sha256
        || profile
            .installation
            .source_sha256()
            .map_err(|_| ReceiverHold::Configuration)?
            != profile.enrollment.installation_source_sha256
    {
        return Err(ReceiverHold::ChangedState);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| ReceiverHold::Engine)?;
    let result = rt.block_on(run(profile, files, installation));
    drop(profile_file);
    result
}
async fn run(
    profile: ServingProfile,
    files: [File; 13],
    installation: receiver_installation_verifier::reference::Verified,
) -> Result<(), ReceiverHold> {
    let [
        key,
        dbkey,
        journal,
        journal_dir,
        lease,
        anchor,
        anchor_dir,
        expiry,
        cache,
        account_dir,
        history,
        listener,
        token,
    ] = files;
    let token = read(&token, 256)?;
    let token = String::from_utf8(token).map_err(|_| ReceiverHold::Configuration)?;
    if !hex64(&token) {
        return Err(ReceiverHold::Configuration);
    }
    let mut history = store::Store::open(
        history,
        &profile.serving_generation,
        &profile
            .enrollment
            .canonical_sha256()
            .map_err(|_| ReceiverHold::Configuration)?,
    )?;
    channel::check_listener(&listener)?;
    let listener = UnixListener::from(OwnedFd::from(listener));
    listener
        .set_nonblocking(true)
        .map_err(|_| ReceiverHold::Configuration)?;
    let Opened {
        mut factory,
        sdk,
        adapter,
        relay_spool,
        _custody,
    } = open_receiver(
        &profile.enrollment,
        profile.receiver_uid,
        profile.endpoints.clone(),
        [
            key,
            dbkey,
            journal,
            journal_dir,
            lease,
            anchor,
            anchor_dir,
            expiry,
            cache,
            account_dir,
        ],
    )?;
    owned_producer::GroupBinding::read(
        &factory.receiver.engine,
        &factory.receiver.group,
        &profile.transport_group,
    )?;
    let forwarder = forward(sdk.clone(), adapter.clone(), relay_spool);
    let result = serve(
        &profile,
        &mut factory,
        &adapter,
        &forwarder,
        Listener {
            socket: listener,
            token,
        },
        &mut history,
        &installation,
    )
    .await;
    forwarder.abort();
    let _ = forwarder.await;
    let shutdown = tokio::time::timeout(Duration::from_secs(5), sdk.shutdown()).await;
    // Exact originals and factory remain owned through transport shutdown.
    drop((factory, _custody));
    if shutdown.is_err() {
        return Err(ReceiverHold::Engine);
    }
    result
}
struct Listener {
    socket: UnixListener,
    token: String,
}
async fn serve(
    profile: &ServingProfile,
    factory: &mut SemanticFactory<SqliteAccountStorage>,
    adapter: &NostrTransportAdapter,
    forwarder: &relay_spool::Forwarder,
    listener: Listener,
    history: &mut store::Store,
    installation: &receiver_installation_verifier::reference::Verified,
) -> Result<(), ReceiverHold> {
    let Listener {
        socket: listener,
        token,
    } = listener;
    tokio::time::timeout(
        Duration::from_secs(30),
        adapter.activate_account(TransportAccountActivation {
            account_id: factory.receiver.engine.self_id(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: factory.receiver.group.clone(),
                transport_group_id: profile.transport_group.clone(),
                endpoints: profile.endpoints.clone(),
            }],
            since: None,
        }),
    )
    .await
    .map_err(|_| ReceiverHold::Engine)?
    .map_err(|_| ReceiverHold::Engine)?;
    let (tx, rx) = mpsc::sync_channel(64);
    let active = Arc::new(AtomicUsize::new(0));
    let mut closure_checked = std::time::Instant::now();
    loop {
        if forwarder.is_finished() {
            return Err(ReceiverHold::Engine);
        }
        for _ in 0..16 {
            match listener.accept() {
                Ok((peer, _)) if active.load(Ordering::Acquire) < 32 => {
                    channel::spawn(
                        peer,
                        profile.hermes_uid,
                        token.clone(),
                        tx.clone(),
                        active.clone(),
                    );
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(ReceiverHold::Engine),
            }
        }
        for _ in 0..16 {
            let Ok(command) = rx.try_recv() else { break };
            match command {
                Command::Call(call) => {
                    installation
                        .check()
                        .map_err(|_| ReceiverHold::ChangedState)?;
                    closure_checked = std::time::Instant::now();
                    let result = dispatch(factory, profile, history, call.request).await;
                    // Journal/native uncertainty stops this owner, never retries
                    // native preparation. Request-shape refusals are harmless.
                    let fatal =
                        matches!(&result, Err(ReceiverHold::Journal | ReceiverHold::Latched));
                    let _ = call.reply.send(result);
                    if fatal {
                        return Err(ReceiverHold::Latched);
                    }
                }
                Command::Replay { after, reply } => {
                    let _ = reply.send(projection::replay(factory, profile, history, after));
                }
            }
        }
        match tokio::time::timeout(Duration::from_millis(20), adapter.receive()).await {
            Ok(Ok(Some(delivery))) => {
                if delivery.account_id != factory.receiver.engine.self_id() {
                    return Err(ReceiverHold::ChangedState);
                }
                match factory.ingest(delivery.message).await {
                    Ok(_) => (),
                    Err(ReceiverHold::Capacity) if !factory.held && !factory.receiver.latched => (),
                    Err(e) => return Err(e),
                }
            }
            Ok(_) => return Err(ReceiverHold::Engine),
            Err(_) => (),
        }
        // Immutable closure is fully reread before commands and periodically
        // while idle; native receive never invokes an external executable.
        if closure_checked.elapsed() >= Duration::from_secs(60) {
            installation
                .check()
                .map_err(|_| ReceiverHold::ChangedState)?;
            closure_checked = std::time::Instant::now();
        }
    }
}
#[path = "protected_serving_dispatch.rs"]
mod dispatch;
use dispatch::dispatch;
#[cfg(test)]
#[path = "protected_serving_tests.rs"]
mod tests;
