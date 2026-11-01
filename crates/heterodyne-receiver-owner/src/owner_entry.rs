//! Fixed root-owned initializer supervision. The caller retains the original
//! lifetime lease and final channel; this entry never reopens private storage.
use crate::{initializer_entry as input, initializer_handoff as handoff, owned_child::OwnedChild};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    time::Duration,
};
type Result<T> = std::result::Result<T, ()>;

pub(super) fn selected_initializer(
    verified: &receiver_installation_verifier::reference::Verified,
) -> Result<File> {
    let path = verified
        .python()
        .parent()
        .ok_or(())?
        .parent()
        .ok_or(())?
        .parent()
        .ok_or(())?
        .join("bin/heterodyne-receiver-initialize");
    let expected = verified
        .closure()
        .map_err(|_| ())?
        .into_iter()
        .find(|(p, _)| p == &path)
        .ok_or(())?
        .1;
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let before = file.metadata().map_err(|_| ())?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o555
        || before.len() == 0
        || before.len() > 256 * 1024 * 1024
    {
        return Err(());
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if raw.len() as u64 != before.len()
        || hex::encode(Sha256::digest(raw)) != expected
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(());
    }
    verified.check().map_err(|_| ())?;
    Ok(file)
}
pub(super) fn channel() -> Result<(File, File)> {
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
        return Err(());
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}
pub(super) fn validate_handles(handles: &[File; 5], uid: u32) -> Result<()> {
    let mut identities = std::collections::BTreeSet::new();
    let mut device = None;
    for (ordinal, file) in handles.iter().enumerate() {
        let m = file.metadata().map_err(|_| ())?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || flags & (libc::O_PATH | libc::O_APPEND) != 0
            || flags & libc::O_ACCMODE
                != if ordinal <= 2 {
                    libc::O_RDONLY
                } else {
                    libc::O_RDWR
                }
            || m.uid() != uid
            || m.gid() != uid
            || m.mode() & 0o7777
                != match ordinal {
                    0 => 0o700,
                    1 | 2 => 0o400,
                    _ => 0o600,
                }
            || (ordinal == 0 && !m.is_dir())
            || (ordinal != 0 && (!m.is_file() || m.nlink() != 1))
            || !identities.insert((m.dev(), m.ino()))
        {
            return Err(());
        }
        if device.replace(m.dev()).is_some_and(|old| old != m.dev()) {
            return Err(());
        }
    }
    Ok(())
}
pub(crate) fn entry() -> Result<()> {
    if unsafe { libc::geteuid() } != 0
        || std::env::args_os().count() != 1
        || std::env::vars_os().next().is_some()
    {
        return Err(());
    }
    let [original, parent, ledger, lease, expiry, outgoing] =
        [3, 4, 5, 6, 7, 8].map(|fd| unsafe { File::from_raw_fd(fd) });
    let raw = input::protected_bytes(&original)?;
    let profile = input::profile(&raw)?;
    cgka_engine::protected_expiry_policy::verify_descriptor(
        &expiry,
        &profile.expiry_profile_sha256,
    )
    .map_err(|_| ())?;
    let verified = profile.installation.verify().map_err(|_| ())?;
    let executable = selected_initializer(&verified)?;
    let (incoming, child_channel) = channel()?;
    handoff::enable_credentials(&incoming).map_err(|_| ())?;
    let child = OwnedChild::initializer(
        &executable,
        &[
            (3, &original),
            (4, &parent),
            (5, &ledger),
            (6, &lease),
            (7, &expiry),
            (8, &child_channel),
        ],
        lease.try_clone().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let pid = child.pid();
    drop(child_channel);
    let mut ready = libc::pollfd {
        fd: incoming.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = (profile.wait_seconds * 1000).min(i32::MAX as u64) as i32;
    if unsafe { libc::poll(&mut ready, 1, timeout) } != 1 || ready.revents & libc::POLLIN == 0 {
        return Err(());
    }
    let (facts, handles) =
        handoff::receive(&incoming, pid, profile.receiver_uid).map_err(|_| ())?;
    let ceased = child.wait(Duration::from_secs(10)).map_err(|_| ())?;
    if !libc::WIFEXITED(ceased.status) || libc::WEXITSTATUS(ceased.status) != 0 {
        return Err(());
    }
    let retained_lease = ceased.into_lease();
    if facts.schema != "heterodyne-owned-initialization.v1"
        || facts.request_sha256 != profile.request_sha256
        || facts.storage_generation != profile.storage_generation
        || facts.initializer_profile_sha256 != hex::encode(Sha256::digest(&raw))
        || facts.expiry_profile_sha256 != profile.expiry_profile_sha256
        || facts.installation_index_sha256 != profile.installation.index_sha256
        || facts.expected_welcomer != profile.expected_welcomer
        || facts.capability_template != profile.capability_template
        || facts.capability_policy_sha256 != profile.capability_policy_sha256
        || !input::hash(&facts.account, 64)
        || profile.operators.contains(&facts.account)
        || facts.account == profile.expected_welcomer
        || !input::hash(&facts.key_package_ref, 64)
        || !input::hash(&facts.key_package_event_id, 64)
    {
        return Err(());
    }
    validate_handles(&handles, profile.receiver_uid)?;
    if input::protected_bytes(&original)? != raw {
        return Err(());
    }
    verified.check().map_err(|_| ())?;
    handoff::send(&outgoing, &facts, &handles).map_err(|_| ())?;
    // The invoking protected supervisor still owns its original lifetime OFD.
    // Sending these handles does not admit receiver continuation on its own.
    drop(retained_lease);
    drop(lease);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    #[ignore = "actual root dedicated UID899 descriptor custody"]
    fn generated_role_modes_and_access_are_admitted_exactly() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("account");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let account = File::open(&dir).unwrap();
        assert_eq!(unsafe { libc::fchown(account.as_raw_fd(), 899, 899) }, 0);
        let mut handles = vec![account];
        for (n, mode) in [
            ("key", 0o400),
            ("seed", 0o400),
            ("database", 0o600),
            ("lease", 0o600),
        ] {
            let path = dir.join(n);
            std::fs::write(&path, [1u8; 32]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let file = File::options()
                .read(true)
                .write(mode == 0o600)
                .open(path)
                .unwrap();
            assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 899, 899) }, 0);
            handles.push(file);
        }
        let mut handles: [File; 5] = handles.try_into().unwrap();
        validate_handles(&handles, 899).unwrap();
        let original = std::mem::replace(
            &mut handles[1],
            File::options()
                .read(true)
                .write(true)
                .open(dir.join("key"))
                .unwrap(),
        );
        assert!(validate_handles(&handles, 899).is_err());
        handles[1] = original;
        validate_handles(&handles, 899).unwrap();
        std::fs::set_permissions(dir.join("seed"), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_handles(&handles, 899).is_err());
    }
}
