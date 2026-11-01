//! Exact inherited anchor capability checks for the fixed owned startup.
//! Root's path/name binding, cessation, restore policy and admission stay separate.
use super::ReceiverHold;
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

type Result<T> = std::result::Result<T, ReceiverHold>;
fn refused<T>() -> Result<T> {
    Err(ReceiverHold::Configuration)
}

/// Must run before creating any thread or trusted producer child.
/// The first supported dedicated identity requires GID equal to its enrolled UID.
/// No independently observed or caller-selected GID is admitted.
pub(super) fn harden_process(receiver_uid: u32) -> Result<()> {
    let mut uid = [0; 3];
    let mut gid = [0; 3];
    if receiver_uid == 0
        || unsafe { libc::getresuid(&mut uid[0], &mut uid[1], &mut uid[2]) } != 0
        || unsafe { libc::getresgid(&mut gid[0], &mut gid[1], &mut gid[2]) } != 0
        || uid != [receiver_uid; 3]
        || gid != [receiver_uid; 3]
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        return refused();
    }
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return refused();
    }
    let mut observed = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut observed) } != 0
        || observed.rlim_cur != 0
        || observed.rlim_max != 0
    {
        return refused();
    }
    Ok(())
}

/// Checks the SAME open descriptions passed to Journal, never substitute opens.
/// Receiver cannot prove the root-only filename-to-inode binding itself.
pub(super) fn check_descriptors(
    anchor: &File,
    directory: &File,
    journal_directory: &File,
    account_directory: &File,
) -> Result<()> {
    let file = anchor.metadata().map_err(|_| ReceiverHold::Configuration)?;
    let dir = directory
        .metadata()
        .map_err(|_| ReceiverHold::Configuration)?;
    let file_flags = unsafe { libc::fcntl(anchor.as_raw_fd(), libc::F_GETFL) };
    let dir_flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFL) };
    if !file.is_file()
        || file.uid() != 0
        || file.gid() != 0
        || file.mode() & 0o7777 != 0o600
        || file.nlink() != 1
        || !dir.is_dir()
        || dir.uid() != 0
        || dir.gid() != 0
        || dir.mode() & 0o7777 != 0o700
        || file.dev() != dir.dev()
        || file_flags < 0
        || file_flags & libc::O_ACCMODE != libc::O_RDWR
        || file_flags & (libc::O_PATH | libc::O_APPEND) != 0
        || dir_flags < 0
        || dir_flags & libc::O_ACCMODE != libc::O_RDONLY
        || dir_flags & libc::O_PATH != 0
    {
        return refused();
    }
    for other in [journal_directory, account_directory] {
        let metadata = other.metadata().map_err(|_| ReceiverHold::Configuration)?;
        if !metadata.is_dir() || (metadata.dev(), metadata.ino()) == (dir.dev(), dir.ino()) {
            return refused();
        }
    }
    // This is also checked by Journal on these exact descriptions; a second
    // opener cannot acquire the lock. The receiver retains it through shutdown.
    anchor.try_lock().map_err(|_| ReceiverHold::Configuration)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    // Run this exact ignored control under root in an isolated disposable tree.
    // Default non-root tests must not report privileged custody as qualified.
    #[test]
    #[ignore = "requires actual disposable root-owned filesystem fixture"]
    fn anchor_custody_actual_root_metadata_and_same_description_lock() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = tempfile::tempdir().unwrap();
        let protected = root.path().join("anchor");
        let journal = root.path().join("journal");
        let account = root.path().join("account");
        for path in [&protected, &journal, &account] {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();
        let path = protected.join("fixed-generation");
        let anchor = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let directory = File::open(&protected).unwrap();
        let journal = File::open(journal).unwrap();
        let account = File::open(account).unwrap();
        let check = || check_descriptors(&anchor, &directory, &journal, &account);
        check().unwrap();
        let competitor = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(competitor.try_lock().is_err());
        // Rechecking this SAME open description succeeds without changing lock.
        check().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(check().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, protected.join("alias")).unwrap();
        assert!(check().is_err());
        fs::remove_file(protected.join("alias")).unwrap();
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(check().is_err());
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_descriptors(&anchor, &directory, &directory, &account).is_err());
        let read_only = File::open(&path).unwrap();
        assert!(check_descriptors(&read_only, &directory, &journal, &account).is_err());
        let opath = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&protected)
            .unwrap();
        assert!(check_descriptors(&anchor, &opath, &journal, &account).is_err());
        check().unwrap();
        anchor.sync_all().unwrap();
        directory.sync_all().unwrap();
    }

    #[test]
    #[ignore = "requires actual root-to-dedicated-UID process transition"]
    fn anchor_custody_actual_dedicated_process_hardening() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        // Fork child uses only fixed native syscalls and exits without unwinding;
        // never changes the test runner's credentials/dumpability/core policy.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let ok = unsafe {
                libc::setgroups(0, std::ptr::null()) == 0
                    && libc::setresgid(61342, 61342, 61342) == 0
                    && libc::setresuid(61342, 61342, 61342) == 0
            } && harden_process(61342).is_ok()
                && harden_process(61343).is_err();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
    }

    #[test]
    #[ignore = "requires actual dedicated UID with a mismatching primary GID"]
    fn anchor_custody_actual_mismatching_gid_is_refused() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let ok = unsafe {
                libc::setgroups(0, std::ptr::null()) == 0
                    && libc::setresgid(61343, 61343, 61343) == 0
                    && libc::setresuid(61342, 61342, 61342) == 0
            } && harden_process(61342).is_err();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
    }

    #[test]
    fn anchor_custody_refuses_root_as_receiver() {
        assert!(harden_process(0).is_err());
    }
    #[test]
    #[ignore = "actual cross-UID inherited capabilities and proc permissions"]
    fn anchor_custody_actual_uid_cannot_reopen_but_retained_fd_advances() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("anchor");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let directory = File::open(root.path()).unwrap();
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let self_fd =
            std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let credentials = unsafe {
                libc::setgroups(0, std::ptr::null()) == 0
                    && libc::setresgid(61342, 61342, 61342) == 0
                    && libc::setresuid(61342, 61342, 61342) == 0
            };
            if !credentials || harden_process(61342).is_err() {
                unsafe { libc::_exit(1) }
            }
            let path_open = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
            let self_open = unsafe { libc::open(self_fd.as_ptr(), libc::O_RDWR) };
            let written = unsafe { libc::pwrite(file.as_raw_fd(), b"test".as_ptr().cast(), 4, 0) };
            let synced = unsafe {
                libc::fsync(file.as_raw_fd()) == 0 && libc::fsync(directory.as_raw_fd()) == 0
            };
            // A trusted same-UID producer gets no anchor descriptor; nondumpable
            // receiver prevents reopening the parent's inherited capability.
            let parent_path = std::ffi::CString::new(format!(
                "/proc/{}/fd/{}",
                unsafe { libc::getpid() },
                file.as_raw_fd()
            ))
            .unwrap();
            let producer = unsafe { libc::fork() };
            if producer == 0 {
                unsafe {
                    libc::close(file.as_raw_fd());
                }
                let reopened = unsafe { libc::open(parent_path.as_ptr(), libc::O_RDWR) };
                unsafe { libc::_exit(if reopened < 0 { 0 } else { 1 }) }
            }
            let mut status = 1;
            let waited =
                producer > 0 && unsafe { libc::waitpid(producer, &mut status, 0) } == producer;
            unsafe {
                libc::_exit(
                    if path_open < 0
                        && self_open < 0
                        && written == 4
                        && synced
                        && waited
                        && status == 0
                    {
                        0
                    } else {
                        1
                    },
                )
            }
        }
        let mut status = 1;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
        assert_eq!(fs::read(root.path().join("anchor")).unwrap(), b"test");
    }
}
