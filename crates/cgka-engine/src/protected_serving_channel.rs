//! Bounded socket workers own no Engine or semantic constructor.
use super::*;
use std::io::{BufRead, BufReader};
fn socket_option(fd: i32, name: i32) -> Result<i32, ReceiverHold> {
    let mut value = 0i32;
    let mut n = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            (&mut value as *mut i32).cast(),
            &mut n,
        )
    } != 0
        || n as usize != std::mem::size_of::<i32>()
    {
        return Err(ReceiverHold::Configuration);
    }
    Ok(value)
}
pub(super) fn check_listener(file: &File) -> Result<(), ReceiverHold> {
    if socket_option(file.as_raw_fd(), libc::SO_ACCEPTCONN)? != 1
        || socket_option(file.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
    {
        return Err(ReceiverHold::Configuration);
    }
    let mut domain = 0i32;
    let mut n = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            file.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut domain as *mut i32).cast(),
            &mut n,
        )
    } != 0
        || domain != libc::AF_UNIX
    {
        return Err(ReceiverHold::Configuration);
    }
    Ok(())
}
fn authenticated(peer: &UnixStream, uid: u32, token: &str, request: &Value) -> bool {
    let mut c = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut n = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let credentials = unsafe {
        libc::getsockopt(
            peer.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut c as *mut libc::ucred).cast(),
            &mut n,
        )
    } == 0
        && n as usize == std::mem::size_of::<libc::ucred>()
        && c.uid == uid;
    let supplied = request
        .get("auth_token")
        .and_then(Value::as_str)
        .unwrap_or("");
    let diff = supplied
        .as_bytes()
        .iter()
        .zip(token.as_bytes())
        .fold(0u8, |a, (x, y)| a | (x ^ y));
    credentials && supplied.len() == token.len() && diff == 0
}
fn write(peer: &mut UnixStream, id: &Value, mut payload: Value) -> Result<(), ReceiverHold> {
    payload["marmot_agent_control"] = json!(PROTOCOL);
    payload["id"] = id.clone();
    let mut raw = serde_json::to_vec(&payload).map_err(|_| ReceiverHold::Malformed)?;
    raw.push(b'\n');
    if raw.len() > MAX_FRAME {
        return Err(ReceiverHold::Capacity);
    }
    peer.write_all(&raw).map_err(|_| ReceiverHold::Engine)
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(super) fn spawn(
    peer: UnixStream,
    uid: u32,
    token: String,
    tx: mpsc::SyncSender<Command>,
    active: Arc<AtomicUsize>,
) {
    active.fetch_add(1, Ordering::AcqRel);
    let rollback = active.clone();
    if std::thread::Builder::new()
        .name("owned-conversation".into())
        .spawn(move || {
            let _guard = Active(active);
            let _ = connection(peer, uid, &token, tx);
        })
        .is_err()
    {
        rollback.fetch_sub(1, Ordering::AcqRel);
    }
}
fn connection(
    mut peer: UnixStream,
    uid: u32,
    token: &str,
    tx: mpsc::SyncSender<Command>,
) -> Result<(), ReceiverHold> {
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ReceiverHold::Engine)?;
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ReceiverHold::Engine)?;
    let mut raw = Vec::new();
    BufReader::new((&peer).take((MAX_FRAME + 1) as u64))
        .read_until(b'\n', &mut raw)
        .map_err(|_| ReceiverHold::Malformed)?;
    if raw.is_empty() || raw.len() > MAX_FRAME || raw.last() != Some(&b'\n') {
        return Err(ReceiverHold::Capacity);
    }
    let request: Value = serde_json::from_slice(&raw).map_err(|_| ReceiverHold::Malformed)?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if !id.is_string()
        || id.as_str().is_none_or(|s| s.is_empty() || s.len() > 256)
        || request.get("marmot_agent_control").and_then(Value::as_str) != Some(PROTOCOL)
        || !authenticated(&peer, uid, token, &request)
    {
        return Err(ReceiverHold::Configuration);
    }
    let subscribe = request.get("type").and_then(Value::as_str) == Some("subscribe_inbound");
    let (reply, rx) = mpsc::sync_channel(1);
    tx.try_send(Command::Call(Call { request, reply }))
        .map_err(|_| ReceiverHold::Capacity)?;
    match rx
        .recv_timeout(Duration::from_secs(90))
        .map_err(|_| ReceiverHold::Engine)?
    {
        Ok(payload) => write(&mut peer, &id, payload)?,
        Err(_) => {
            write(
                &mut peer,
                &id,
                json!({"type":"error","code":"owned_receiver_hold","message":"request held","retryable":false}),
            )?;
            return Ok(());
        }
    }
    if !subscribe {
        return Ok(());
    }
    let mut after = 0;
    loop {
        let (reply, rx) = mpsc::sync_channel(1);
        tx.try_send(Command::Replay { after, reply })
            .map_err(|_| ReceiverHold::Capacity)?;
        let (events, next) = rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| ReceiverHold::Engine)??;
        if next < after {
            return Err(ReceiverHold::ChangedState);
        }
        let idle = events.is_empty() && after == next;
        for event in events {
            write(&mut peer, &id, event)?;
        }
        after = next;
        if idle {
            // A finite ping detects a dead subscriber without inventing a
            // conversation event or advancing its durable replay cursor.
            write(
                &mut peer,
                &id,
                json!({"type":"ack","operation":"subscription_alive"}),
            )?;
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
