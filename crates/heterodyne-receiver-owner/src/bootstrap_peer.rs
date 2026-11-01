//! Source-owned dedicated consumer peer. The stream is CREATED after UID drop,
//! so the receiver observes the actual consumer credential, never a root-made
//! socket impersonating it. The helper inherits no account or publication FDs.
use std::{
    fs::File,
    io::{Read, Write},
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
    time::Duration,
};
type Result<T> = std::io::Result<T>;
fn hold() -> std::io::Error {
    std::io::Error::other("consumer handoff refused")
}
#[repr(align(16))]
struct Control([u8; 128]);
pub(crate) struct Peer {
    pid: i32,
    channel: File,
    pub(crate) stream: File,
    pub(crate) nonce: [u8; 32],
    reaped: bool,
}
impl Peer {
    pub(crate) fn start(timeout: Duration) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0
            || timeout.is_zero()
            || timeout > Duration::from_secs(86400)
        {
            return Err(hold());
        }
        let mut fds = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let (channel, other) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        let yes = 1i32;
        if unsafe {
            libc::setsockopt(
                channel.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&yes as *const i32).cast(),
                4,
            )
        } != 0
        {
            return Err(hold());
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| hold())?;
        let placeholder = File::open("/dev/null")?;
        let parent = unsafe { libc::getpid() };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if pid == 0 {
            // Before constructing a Rust stream, discard every inherited private
            // handle. This fixed helper has no executable/argv/operation input.
            unsafe {
                if libc::dup2(other.as_raw_fd(), 3) < 0
                    || libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0) < 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(898, 898, 898) != 0
                    || libc::setresuid(898, 898, 898) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                {
                    libc::_exit(125);
                }
            }
            let result = helper(&nonce, timeout);
            unsafe {
                libc::_exit(if result.is_ok() { 0 } else { 125 });
            }
        }
        drop(other);
        let mut peer = Self {
            pid,
            channel,
            stream: placeholder,
            nonce,
            reaped: false,
        };
        peer.ready(Duration::from_secs(5))?;
        peer.stream = peer.receive_stream()?;
        Ok(peer)
    }
    fn ready(&self, timeout: Duration) -> Result<()> {
        let mut p = libc::pollfd {
            fd: self.channel.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut p, 1, timeout.as_millis().min(i32::MAX as u128) as i32) } != 1
            || p.revents & libc::POLLIN == 0
        {
            return Err(hold());
        }
        Ok(())
    }
    fn receive_stream(&self) -> Result<File> {
        let mut byte = [0u8; 1];
        let mut c = Control([0; 128]);
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = c.0.as_mut_ptr().cast();
        msg.msg_controllen = 128;
        let n =
            unsafe { libc::recvmsg(self.channel.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        let mut handles = Vec::new();
        let mut credential = None;
        let mut valid = true;
        unsafe {
            let mut p = libc::CMSG_FIRSTHDR(&msg);
            while !p.is_null() {
                if (*p).cmsg_level != libc::SOL_SOCKET {
                    valid = false;
                } else if (*p).cmsg_type == libc::SCM_RIGHTS {
                    let bytes = (*p).cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                    if !bytes.is_multiple_of(size_of::<i32>()) {
                        valid = false;
                    }
                    for i in 0..bytes / size_of::<i32>() {
                        handles.push(File::from_raw_fd(std::ptr::read_unaligned(
                            libc::CMSG_DATA(p).cast::<i32>().add(i),
                        )));
                    }
                } else if (*p).cmsg_type == libc::SCM_CREDENTIALS
                    && (*p).cmsg_len == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
                    && credential.is_none()
                {
                    credential = Some(std::ptr::read_unaligned(
                        libc::CMSG_DATA(p).cast::<libc::ucred>(),
                    ));
                } else {
                    valid = false;
                }
                p = libc::CMSG_NXTHDR(&msg, p);
            }
        }
        let u = credential.ok_or_else(hold)?;
        if n != 1
            || byte != [1]
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || !valid
            || handles.len() != 1
            || (u.pid, u.uid, u.gid) != (self.pid, 898, 898)
        {
            return Err(hold());
        }
        Ok(handles.remove(0))
    }
    pub(crate) fn result(mut self, timeout: Duration) -> Result<Vec<u8>> {
        self.ready(timeout)?;
        let mut raw = vec![0; 65536];
        let n = unsafe {
            libc::recv(
                self.channel.as_raw_fd(),
                raw.as_mut_ptr().cast(),
                raw.len(),
                libc::MSG_TRUNC,
            )
        };
        if n <= 0 || n as usize > raw.len() {
            return Err(hold());
        }
        raw.truncate(n as usize);
        let mut status = 0;
        loop {
            let r = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if r == self.pid {
                self.reaped = true;
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(hold());
            }
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(hold());
        }
        Ok(raw)
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                let mut status = 0;
                while libc::waitpid(self.pid, &mut status, 0) < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                }
            }
        }
    }
}
fn helper(nonce: &[u8; 32], timeout: Duration) -> Result<()> {
    let (mut local, receiver) = UnixStream::pair()?;
    local.set_read_timeout(Some(timeout))?;
    local.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut byte = [1u8];
    let mut c = Control([0; 128]);
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = c.0.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
    unsafe {
        let p = libc::CMSG_FIRSTHDR(&msg);
        (*p).cmsg_level = libc::SOL_SOCKET;
        (*p).cmsg_type = libc::SCM_RIGHTS;
        (*p).cmsg_len = libc::CMSG_LEN(4) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(p).cast::<i32>(), receiver.as_raw_fd());
        if libc::sendmsg(3, &msg, libc::MSG_NOSIGNAL) != 1 {
            return Err(hold());
        }
    }
    drop(receiver);
    local.write_all(nonce)?;
    let mut len = [0; 4];
    local.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > 65536 {
        return Err(hold());
    }
    let mut raw = vec![0; len];
    local.read_exact(&mut raw)?;
    if unsafe { libc::send(3, raw.as_ptr().cast(), raw.len(), libc::MSG_NOSIGNAL) }
        != raw.len() as isize
    {
        return Err(hold());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "actual root fork and dedicated consumer UID898"]
    fn actual_consumer_credential_nonce_and_framed_result() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let peer = Peer::start(Duration::from_secs(5)).unwrap();
        let mut u: libc::ucred = unsafe { zeroed() };
        let mut len = size_of::<libc::ucred>() as u32;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    peer.stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut u as *mut libc::ucred).cast(),
                    &mut len,
                )
            },
            0
        );
        assert_eq!((u.pid, u.uid, u.gid), (peer.pid, 898, 898));
        let mut stream =
            UnixStream::from(std::os::fd::OwnedFd::from(peer.stream.try_clone().unwrap()));
        let mut nonce = [0; 32];
        stream.read_exact(&mut nonce).unwrap();
        assert_eq!(nonce, peer.nonce);
        let raw = b"{\"actual\":\"result\"}";
        stream.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
        stream.write_all(raw).unwrap();
        assert_eq!(peer.result(Duration::from_secs(5)).unwrap(), raw);
    }
    #[test]
    #[ignore = "actual root fork and dedicated consumer UID898"]
    fn malformed_or_oversize_frame_cannot_produce_acknowledgement() {
        let peer = Peer::start(Duration::from_secs(1)).unwrap();
        let mut stream =
            UnixStream::from(std::os::fd::OwnedFd::from(peer.stream.try_clone().unwrap()));
        let mut nonce = [0; 32];
        stream.read_exact(&mut nonce).unwrap();
        stream.write_all(&65537u32.to_be_bytes()).unwrap();
        assert!(peer.result(Duration::from_secs(2)).is_err());
    }
}
