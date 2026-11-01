//! One kernel-credentialed packet containing public initialization facts and
//! the original storage OFDs. Parsing facts alone never admits continuation.
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd};

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Facts {
    pub(crate) schema: String,
    pub(crate) request_sha256: String,
    pub(crate) storage_generation: String,
    pub(crate) initializer_profile_sha256: String,
    pub(crate) expiry_profile_sha256: String,
    pub(crate) installation_index_sha256: String,
    pub(crate) account: String,
    pub(crate) expected_welcomer: String,
    pub(crate) key_package_ref: String,
    pub(crate) key_package_event_id: String,
    pub(crate) capability_template: String,
    pub(crate) capability_policy_sha256: String,
}
#[repr(align(16))]
struct Control([u8; 256]);
fn hold() -> io::Error {
    io::Error::other("initializer handoff refused")
}
fn socket(file: &File) -> io::Result<()> {
    for (name, expected) in [
        (libc::SO_TYPE, libc::SOCK_SEQPACKET),
        (libc::SO_DOMAIN, libc::AF_UNIX),
    ] {
        let mut value = 0i32;
        let mut len = size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                file.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                (&mut value as *mut i32).cast(),
                &mut len,
            )
        } != 0
            || value != expected
        {
            return Err(hold());
        }
    }
    Ok(())
}
pub(crate) fn enable_credentials(file: &File) -> io::Result<()> {
    socket(file)?;
    let yes = 1i32;
    if unsafe {
        libc::setsockopt(
            file.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&yes as *const i32).cast(),
            size_of::<i32>() as u32,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn send(file: &File, facts: &Facts, handles: &[File; 5]) -> io::Result<()> {
    socket(file)?;
    let raw = serde_json::to_vec(facts).map_err(|_| hold())?;
    if raw.len() > 8192 {
        return Err(hold());
    }
    let fds = handles.each_ref().map(AsRawFd::as_raw_fd);
    let mut control = Control([0; 256]);
    let mut iov = libc::iovec {
        iov_base: raw.as_ptr().cast_mut().cast(),
        iov_len: raw.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<[i32; 5]>() as u32) } as usize;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(size_of::<[i32; 5]>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(c),
            size_of::<[i32; 5]>(),
        );
        if libc::sendmsg(file.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) != raw.len() as isize {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
/// Caller retains OwnedChild and waits for positive cessation separately. Even
/// authentic child facts do not substitute for original profile/native checks.
pub(crate) fn receive(file: &File, pid: libc::pid_t, uid: u32) -> io::Result<(Facts, [File; 5])> {
    socket(file)?;
    let mut raw = [0u8; 8192];
    let mut control = Control([0; 256]);
    let mut iov = libc::iovec {
        iov_base: raw.as_mut_ptr().cast(),
        iov_len: raw.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = 256;
    let n = unsafe {
        libc::recvmsg(
            file.as_raw_fd(),
            &mut msg,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut handles = Vec::new();
    let mut credentials = None;
    let mut valid = true;
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level != libc::SOL_SOCKET {
                valid = false;
            } else if (*c).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*c).cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                if !bytes.is_multiple_of(size_of::<i32>()) {
                    valid = false;
                }
                for i in 0..bytes / size_of::<i32>() {
                    handles.push(File::from_raw_fd(std::ptr::read_unaligned(
                        libc::CMSG_DATA(c).cast::<i32>().add(i),
                    )));
                }
            } else if (*c).cmsg_type == libc::SCM_CREDENTIALS
                && (*c).cmsg_len == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
                && credentials.is_none()
            {
                credentials = Some(std::ptr::read_unaligned(
                    libc::CMSG_DATA(c).cast::<libc::ucred>(),
                ));
            } else {
                valid = false;
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    let credential = credentials.ok_or_else(hold)?;
    if !valid
        || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || handles.len() != 5
        || credential.pid != pid
        || credential.uid != uid
        || credential.gid != uid
    {
        return Err(hold());
    }
    let facts: Facts = serde_json::from_slice(&raw[..n as usize]).map_err(|_| hold())?;
    if serde_json::to_vec(&facts).map_err(|_| hold())? != raw[..n as usize] {
        return Err(hold());
    }
    Ok((facts, handles.try_into().map_err(|_| hold())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    fn pair() -> (File, File) {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
    }
    fn facts() -> Facts {
        Facts {
            schema: "heterodyne-owned-initialization.v1".into(),
            request_sha256: "ab".repeat(32),
            storage_generation: "cd".repeat(32),
            initializer_profile_sha256: "ef".repeat(32),
            expiry_profile_sha256: "12".repeat(32),
            installation_index_sha256: "23".repeat(32),
            account: "34".repeat(32),
            expected_welcomer: "78".repeat(32),
            key_package_event_id:
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            key_package_ref: "45".repeat(32),
            capability_template: "routing-only-v1".into(),
            capability_policy_sha256: "56".repeat(32),
        }
    }
    #[test]
    #[ignore = "actual equal-UID/GID custody qualification under root"]
    fn packet_credential_and_original_ofd_transfer() {
        let (a, b) = pair();
        enable_credentials(&a).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let original = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join("lease"))
            .unwrap();
        original.try_lock().unwrap();
        let independent = File::options()
            .read(true)
            .write(true)
            .open(dir.path().join("lease"))
            .unwrap();
        let handles = std::array::from_fn(|_| original.try_clone().unwrap());
        send(&b, &facts(), &handles).unwrap();
        let (result, received) =
            receive(&a, unsafe { libc::getpid() }, unsafe { libc::geteuid() }).unwrap();
        assert_eq!(result, facts());
        drop(handles);
        drop(original);
        assert!(independent.try_lock().is_err());
        drop(received);
        independent.try_lock().unwrap();
        let handles = std::array::from_fn(|_| independent.try_clone().unwrap());
        send(&b, &facts(), &handles).unwrap();
        assert!(receive(&a, -1, unsafe { libc::geteuid() }).is_err());
        send(&b, &facts(), &handles).unwrap();
        assert!(receive(&a, unsafe { libc::getpid() }, unsafe { libc::geteuid() }).is_ok());
    }
    #[test]
    fn wrong_socket_type_refuses_before_io() {
        let (a, _) = UnixDatagram::pair().unwrap();
        let owned: std::os::fd::OwnedFd = a.into();
        let file = File::from(owned);
        assert!(enable_credentials(&file).is_err());
    }
}
