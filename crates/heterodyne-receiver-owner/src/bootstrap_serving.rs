//! Closed serving choice made before initialization. Root retains the listener
//! and token; the dropped-UID child owns the only native account engine.
use super::*;
use serde::Deserialize;
use std::os::unix::net::UnixListener;
const SOCKET: &str = "/run/heterodyne-receiver/hermes/control.sock";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Channel {
    schema: String,
    hermes_uid: u32,
}
pub(super) struct Inputs {
    config: File,
    token: File,
    listener: File,
    hermes_uid: u32,
}
impl Inputs {
    pub(super) fn inherited() -> Result<Self> {
        let config = inherited(8)?;
        let token = inherited(9)?;
        let listener = inherited(10)?;
        let channel: Channel =
            serde_json::from_slice(&input::protected_bytes(&config)?).map_err(|_| ())?;
        if channel.schema != "heterodyne-serving-channel.v1"
            || channel.hermes_uid == 0
            || channel.hermes_uid == 899
            || channel.hermes_uid == 898
        {
            return Err(());
        }
        let token_bytes = input::protected_bytes(&token)?;
        if !std::str::from_utf8(&token_bytes).is_ok_and(|s| input::hash(s, 64)) {
            return Err(());
        }
        let socket = UnixListener::from(std::os::fd::OwnedFd::from(
            listener.try_clone().map_err(|_| ())?,
        ));
        if socket.local_addr().map_err(|_| ())?.as_pathname() != Some(Path::new(SOCKET)) {
            return Err(());
        }
        let mut accepting = 0i32;
        let mut n = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                (&mut accepting as *mut i32).cast(),
                &mut n,
            )
        } != 0
            || accepting != 1
        {
            return Err(());
        }
        // Publication/card inputs must never select a hidden effect lane.
        for fd in [13, 14, 15, 18] {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                return Err(());
            }
        }
        Ok(Self {
            config,
            token,
            listener,
            hermes_uid: channel.hermes_uid,
        })
    }
}
pub(super) struct Custody<'a> {
    pub state: &'a File,
    pub key: &'a File,
    pub seed: &'a File,
    pub journal: &'a File,
    pub journals: &'a File,
    pub storage_lease: &'a File,
    pub anchor: &'a File,
    pub anchors: &'a File,
    pub expiry: &'a File,
    pub cache: &'a File,
    pub account: &'a File,
    pub lease: &'a File,
}
pub(super) fn run(
    inputs: Inputs,
    p: &input::Profile,
    enrollment: &Value,
    transport_group: &[Value],
    verified: &receiver_installation_verifier::reference::Verified,
    custody: Custody<'_>,
) -> Result<()> {
    let Custody {
        state,
        key,
        seed,
        journal,
        journals,
        storage_lease,
        anchor,
        anchors,
        expiry,
        cache,
        account,
        lease,
    } = custody;
    let profile = json!({"schema":"heterodyne-protected-receiver-serving.v1", "receiver_uid":899,
        "hermes_uid":inputs.hermes_uid,"serving_generation":p.storage_generation,
        "enrollment":enrollment,"endpoints":p.inbox_endpoints,"transport_group":transport_group,
        "installation":p.installation});
    let profile = record(state, "05-serving-profile.json", &profile)?;
    let history = create(state, "conversation-delivery.jsonl", 899, 0o600, b"")?;
    let exe = crate::owner_entry::selected(verified, "protected-receiver")?;
    record(
        state,
        "06-serving-issued.json",
        &json!({"automatic_replay_forbidden":true,
        "channel_profile_sha256":hex::encode(Sha256::digest(input::protected_bytes(&inputs.config)?)),
        "server_peer_uid":0}),
    )?;
    let child = OwnedChild::serving(
        &exe,
        &[
            (3, &profile),
            (4, key),
            (5, seed),
            (6, journal),
            (7, journals),
            (8, storage_lease),
            (9, anchor),
            (10, anchors),
            (11, expiry),
            (12, cache),
            (13, account),
            (14, &history),
            (15, &inputs.listener),
            (16, &inputs.token),
        ],
        lease.try_clone().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    // Local variables in the caller retain ALL original OFDs for the entire
    // serving lifetime. Neither a socket nor exit zero is a readiness receipt.
    let cessation = child.wait_serving().map_err(|_| ())?;
    record(
        state,
        "07-serving-ceased.json",
        &json!({"status":cessation.status,
        "requires_reconciliation":true,"automatic_replay_forbidden":true}),
    )?;
    drop(cessation);
    Err(())
}
