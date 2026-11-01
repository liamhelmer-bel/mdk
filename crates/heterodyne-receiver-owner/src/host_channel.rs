//! Fixed root-parent transport. Kernel credentials and retained descriptors are
//! required on every record; these mechanics alone construct no consent.
use std::{
    fs::File,
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd},
};
type Result<T> = std::result::Result<T, ()>;
pub(crate) const MAX_NATIVE: usize = 256 * 1024;
#[repr(align(16))]
struct Control([u8; 128]);
/// Establish capacity before an unprivileged helper can consume a receipt.
pub(crate) fn capacity(channel: &File) -> Result<()> {
    let capacity = MAX_NATIVE as libc::c_int;
    if unsafe {
        libc::setsockopt(
            channel.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&capacity as *const libc::c_int).cast(),
            std::mem::size_of_val(&capacity) as u32,
        )
    } != 0
    {
        return Err(());
    }
    let mut actual: libc::c_int = 0;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    let read_capacity = |actual: &mut libc::c_int, size: &mut libc::socklen_t| unsafe {
        libc::getsockopt(
            channel.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (actual as *mut libc::c_int).cast(),
            size,
        )
    };
    if read_capacity(&mut actual, &mut size) != 0 {
        return Err(());
    }
    // Linux accounts seqpacket framing against the doubled send buffer. A
    // restrictive host sysctl must either be overridden by this root sender or
    // refuse before sending; setting SO_SNDBUF alone does not establish capacity.
    if actual < capacity + 32
        && (unsafe {
            libc::setsockopt(
                channel.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUFFORCE,
                (&capacity as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
            || read_capacity(&mut actual, &mut size) != 0
            || actual < capacity + 32)
    {
        return Err(());
    }
    Ok(())
}
pub(crate) fn send(channel: &File, raw: &[u8], handle: Option<&File>) -> Result<()> {
    if raw.is_empty() || raw.len() > MAX_NATIVE {
        return Err(());
    }
    capacity(channel)?;
    let mut control = Control([0; 128]);
    let mut iov = libc::iovec {
        iov_base: raw.as_ptr().cast_mut().cast(),
        iov_len: raw.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(file) = handle {
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize;
        unsafe {
            let p = libc::CMSG_FIRSTHDR(&msg);
            (*p).cmsg_level = libc::SOL_SOCKET;
            (*p).cmsg_type = libc::SCM_RIGHTS;
            (*p).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(p).cast::<i32>(), file.as_raw_fd());
        }
    }
    if unsafe { libc::sendmsg(channel.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) } != raw.len() as isize
    {
        return Err(());
    }
    Ok(())
}
pub(crate) fn receive(
    channel: &File,
    pid: i32,
    maximum: usize,
    handle: bool,
) -> Result<(Vec<u8>, Option<File>)> {
    if maximum == 0 || maximum > MAX_NATIVE {
        return Err(());
    }
    let mut raw = vec![0u8; maximum];
    let mut control = Control([0; 128]);
    let mut iov = libc::iovec {
        iov_base: raw.as_mut_ptr().cast(),
        iov_len: raw.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = control.0.len();
    let n = unsafe { libc::recvmsg(channel.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(());
    }
    let mut files = Vec::new();
    let mut credentials = None;
    let mut valid = true;
    unsafe {
        let mut p = libc::CMSG_FIRSTHDR(&msg);
        while !p.is_null() {
            if (*p).cmsg_level != libc::SOL_SOCKET {
                valid = false;
            } else if (*p).cmsg_type == libc::SCM_CREDENTIALS
                && (*p).cmsg_len == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
                && credentials.is_none()
            {
                credentials = Some(std::ptr::read_unaligned(
                    libc::CMSG_DATA(p).cast::<libc::ucred>(),
                ));
            } else if (*p).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*p).cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
                if !bytes.is_multiple_of(size_of::<i32>()) {
                    valid = false;
                }
                for i in 0..bytes / size_of::<i32>() {
                    files.push(File::from_raw_fd(std::ptr::read_unaligned(
                        libc::CMSG_DATA(p).cast::<i32>().add(i),
                    )));
                }
            } else {
                valid = false;
            }
            p = libc::CMSG_NXTHDR(&msg, p);
        }
    }
    let credential = credentials.ok_or(())?;
    if n <= 0
        || n as usize > maximum
        || msg.msg_flags & !libc::MSG_CMSG_CLOEXEC != 0
        || !valid
        || (credential.pid, credential.uid, credential.gid) != (pid, 0, 0)
        || files.len() != usize::from(handle)
    {
        return Err(());
    }
    raw.truncate(n as usize);
    Ok((raw, files.pop()))
}
pub(crate) fn nonce() -> Result<([u8; 32], File)> {
    let mut raw = [0; 32];
    getrandom::fill(&mut raw).map_err(|_| ())?;
    let fd = unsafe {
        libc::memfd_create(
            c"heterodyne-owned-nonce".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::pwrite(file.as_raw_fd(), raw.as_ptr().cast(), raw.len(), 0) }
        != raw.len() as isize
        || unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
    {
        return Err(());
    }
    let readonly = File::open(format!("/proc/self/fd/{fd}")).map_err(|_| ())?;
    Ok((raw, readonly))
}
pub(crate) fn read_nonce(file: &File) -> Result<[u8; 32]> {
    use std::os::unix::fs::{FileExt, MetadataExt};
    let m = file.metadata().map_err(|_| ())?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.len() != 32
        || m.nlink() != 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
            != libc::O_RDONLY
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } & seals != seals
    {
        return Err(());
    }
    let mut raw = [0; 32];
    file.read_exact_at(&mut raw, 0).map_err(|_| ())?;
    Ok(raw)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_is_established_before_unprivileged_handoff() {
        let (sender, _receiver) = crate::owner_entry::channel().unwrap();
        let small = 1024i32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    sender.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&small as *const i32).cast(),
                    size_of::<i32>() as u32,
                )
            },
            0
        );
        capacity(&sender).unwrap();
        let mut actual = 0i32;
        let mut size = size_of::<i32>() as u32;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    sender.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&mut actual as *mut i32).cast(),
                    &mut size,
                )
            },
            0
        );
        assert!(actual >= MAX_NATIVE as i32 + 32);
        let invalid = File::open("/dev/null").unwrap();
        assert!(capacity(&invalid).is_err());
    }
    #[test]
    #[ignore = "actual root SCM credentials and sealed root memfd"]
    fn actual_root_records_are_bounded_and_nonce_sealed() {
        let (a, b) = crate::owner_entry::channel().unwrap();
        crate::initializer_handoff::enable_credentials(&a).unwrap();
        let (nonce, file) = nonce().unwrap();
        assert_eq!(read_nonce(&file).unwrap(), nonce);
        let raw = vec![b'x'; MAX_NATIVE];
        send(&b, &raw, Some(&file)).unwrap();
        let (got, fd) = receive(&a, unsafe { libc::getpid() }, MAX_NATIVE, true).unwrap();
        assert_eq!(got, raw);
        assert_eq!(read_nonce(&fd.unwrap()).unwrap(), nonce);
        send(&b, b"xx", None).unwrap();
        assert!(receive(&a, unsafe { libc::getpid() }, 1, false).is_err());
        send(&b, b"a", None).unwrap();
        assert!(receive(&a, unsafe { libc::getpid() } + 1, 1, false).is_err());
        assert!(send(&b, &vec![0; MAX_NATIVE + 1], None).is_err());
        assert!(unsafe { libc::pwrite(file.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) } < 0);
    }
}
