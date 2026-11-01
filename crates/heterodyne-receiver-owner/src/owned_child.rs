//! Fixed executable subprocess custody. A positive wait retains the exact lease
//! OFD; timeout/drop kills the namespace init and waits, never infers completion.
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("owned child refused")]
    Hold,
    #[error("owned child syscall failed")]
    Io(#[from] io::Error),
}
type Result<T> = std::result::Result<T, Error>;

pub(crate) struct OwnedChild {
    pid: libc::pid_t,
    pidfd: File,
    lease: Option<File>,
    reaped: bool,
}
pub(crate) struct Cessation {
    pub(crate) status: i32,
    lease: File,
}
impl Cessation {
    pub(crate) fn into_lease(self) -> File {
        self.lease
    }
}

fn duplicate(file: &File) -> Result<File> {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl OwnedChild {
    /// Called only by fixed source composition after its profile/custody checks.
    /// No process, authority context or executable path can arrive over JSON.
    pub(crate) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub(crate) fn initializer(
        executable: &File,
        descriptors: &[(RawFd, &File)],
        lease: File,
    ) -> Result<Self> {
        if descriptors.len() != 6 || !(3..=8).all(|n| descriptors.iter().any(|(fd, _)| *fd == n)) {
            return Err(Error::Hold);
        }
        Self::launch(
            executable,
            descriptors,
            lease,
            &[CString::new("heterodyne-receiver-initialize").unwrap()],
            9,
            None,
        )
    }

    pub(crate) fn owner_init(
        executable: &File,
        descriptors: &[(RawFd, &File)],
        lease: File,
    ) -> Result<Self> {
        if descriptors.len() != 6 || !(3..=8).all(|n| descriptors.iter().any(|(fd, _)| *fd == n)) {
            return Err(Error::Hold);
        }
        Self::launch(
            executable,
            descriptors,
            lease,
            &[CString::new("heterodyne-receiver-owner-init").unwrap()],
            9,
            None,
        )
    }

    pub(crate) fn receiver(
        executable: &File,
        descriptors: &[(RawFd, &File)],
        lease: File,
        fresh: bool,
    ) -> Result<Self> {
        let last = if fresh { 16 } else { 18 };
        if descriptors.len() != (last - 2) as usize
            || !(3..=last).all(|n| descriptors.iter().any(|(fd, _)| *fd == n))
        {
            return Err(Error::Hold);
        }
        Self::launch(
            executable,
            descriptors,
            lease,
            &[CString::new(if fresh {
                "heterodyne-protected-receiver-enroll"
            } else {
                "heterodyne-protected-receiver"
            })
            .unwrap()],
            19,
            Some(899),
        )
    }

    fn launch(
        executable: &File,
        descriptors: &[(RawFd, &File)],
        lease: File,
        arguments: &[CString],
        parent_slot: RawFd,
        receiver_uid: Option<u32>,
    ) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0
            || !cfg!(target_arch = "x86_64")
            || descriptors.len() > 16
            || arguments.is_empty()
        {
            return Err(Error::Hold);
        }
        let meta = executable.metadata()?;
        let flags = unsafe { libc::fcntl(executable.as_raw_fd(), libc::F_GETFL) };
        if !meta.is_file()
            || meta.uid() != 0
            || meta.gid() != 0
            || meta.nlink() != 1
            || meta.mode() & 0o7022 != 0
            || meta.mode() & 0o111 == 0
            || flags < 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Err(Error::Hold);
        }
        let mut targets = std::collections::BTreeSet::new();
        let mut retained = Vec::new();
        for (target, file) in descriptors {
            if !(3..=18).contains(target) || *target == parent_slot || !targets.insert(*target) {
                return Err(Error::Hold);
            }
            retained.push((*target, duplicate(file)?));
        }
        let executable = duplicate(executable)?;
        let null = File::options().read(true).write(true).open("/dev/null")?;
        let null = duplicate(&null)?;
        let mut argv: Vec<_> = arguments.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());
        let empty = c"";
        let env = [std::ptr::null::<libc::c_char>()];
        let mut pidfd: libc::c_int = -1;
        let parentfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        if parentfd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let parentfd = unsafe { File::from_raw_fd(parentfd as i32) };
        let parentfd = duplicate(&parentfd)?;
        // Linux x86_64 raw clone has fork semantics without a user stack. All
        // child operations below are libc/syscalls over preallocated buffers.
        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_NEWPID | libc::CLONE_PIDFD | libc::SIGCHLD,
                std::ptr::null::<libc::c_void>(),
                &mut pidfd,
                std::ptr::null::<libc::c_void>(),
                0,
            )
        };
        if pid < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if pid == 0 {
            unsafe {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    libc::_exit(125);
                }
                let mut parent_poll = libc::pollfd {
                    fd: parentfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if libc::poll(&mut parent_poll, 1, 0) != 0 {
                    libc::_exit(125);
                }
                for target in 0..=2 {
                    if libc::dup2(null.as_raw_fd(), target) < 0 {
                        libc::_exit(125);
                    }
                }
                for (target, file) in &retained {
                    if libc::dup2(file.as_raw_fd(), *target) < 0 {
                        libc::_exit(125);
                    }
                }
                // CLOEXEC all unexpected inherited handles, including private
                // account/credential handles from the supervising process.
                if libc::syscall(
                    libc::SYS_close_range,
                    20u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
                {
                    libc::_exit(125);
                }
                if libc::dup2(parentfd.as_raw_fd(), parent_slot) < 0 {
                    libc::_exit(125);
                }
                for target in 3..=19 {
                    if target != parent_slot && !targets.contains(&target) {
                        libc::close(target);
                    }
                }
                if libc::chdir(c"/".as_ptr()) < 0 {
                    libc::_exit(125);
                }
                libc::umask(0o077);
                if let Some(uid) = receiver_uid
                    && (libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setresgid(uid, uid, uid) != 0
                        || libc::setresuid(uid, uid, uid) != 0
                        || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                        || libc::poll(&mut parent_poll, 1, 0) != 0)
                {
                    libc::_exit(125);
                }
                libc::syscall(
                    libc::SYS_execveat,
                    executable.as_raw_fd(),
                    empty.as_ptr(),
                    argv.as_ptr(),
                    env.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                libc::_exit(126);
            }
        }
        Ok(Self {
            pid: pid as libc::pid_t,
            pidfd: unsafe { File::from_raw_fd(pidfd) },
            lease: Some(lease),
            reaped: false,
        })
    }

    fn reap(&mut self) -> Result<i32> {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.reaped = true;
                return Ok(status);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error.into());
            }
        }
    }
    pub(crate) fn wait(mut self, timeout: Duration) -> Result<Cessation> {
        crate::supervision::ready(&self.pidfd, timeout).map_err(|_| Error::Hold)?;
        let status = self.reap()?;
        Ok(Cessation {
            status,
            lease: self.lease.take().ok_or(Error::Hold)?,
        })
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            // Killing PID1 tears down its descendants in this owned PIDns.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            let _ = self.reap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::FileExt, time::Instant};

    #[test]
    #[ignore = "actual root tmpfs, receiver UID899 and owned PID namespace"]
    fn receiver_inherits_private_ephemeral_cache() {
        const CONTROL: &str = "OIZOH_CACHE_MOUNT_CHILD";
        assert_eq!(unsafe { libc::geteuid() }, 0);
        if std::env::var_os(CONTROL).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "owned_child::tests::receiver_inherits_private_ephemeral_cache",
                    "--ignored",
                    "--nocapture",
                ])
                .env(CONTROL, "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let material = dir.path().join("material");
        std::fs::create_dir(&material).unwrap();
        let path = CString::new(material.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            assert_eq!(libc::chown(path.as_ptr(), 899, 899), 0);
            assert_eq!(libc::chmod(path.as_ptr(), 0o700), 0);
        }
        let parent = crate::material_mount::bind(&File::open(&material).unwrap(), 899).unwrap();
        let output = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join("out"))
            .unwrap();
        let lease = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join("lease"))
            .unwrap();
        lease.try_lock().unwrap();
        let old_cache = File::open(dir.path()).unwrap();
        assert_eq!(
            old_cache.metadata().unwrap().dev(),
            output.metadata().unwrap().dev()
        );
        assert!(crate::cache_mount::create(&[]).is_err());
        let cache = crate::cache_mount::create(&[&parent, &output]).unwrap();
        assert_ne!(
            cache.metadata().unwrap().dev(),
            output.metadata().unwrap().dev()
        );
        assert!(
            crate::cache_mount::create(&[&parent, &output]).is_err(),
            "no adoption of existing mount"
        );
        let script = "import os; assert os.getpid()==1 and os.getuid()==899 and os.getgid()==899; assert os.fstat(15).st_dev != os.fstat(6).st_dev; assert os.fstat(15).st_uid==899; f=os.open('.',os.O_TMPFILE|os.O_RDWR,0o600,dir_fd=15); os.write(f,b'cache'); assert os.fstat(f).st_nlink==0; os.write(9,b'actual-cache')";
        let args = [
            CString::new("python3").unwrap(),
            CString::new("-I").unwrap(),
            CString::new("-S").unwrap(),
            CString::new("-B").unwrap(),
            CString::new("-c").unwrap(),
            CString::new(script).unwrap(),
        ];
        let descriptors = (3..=16)
            .map(|fd| (fd, if fd == 15 { &cache } else { &output }))
            .collect::<Vec<_>>();
        let child = OwnedChild::launch(
            &File::open("/usr/bin/python3.12").unwrap(),
            &descriptors,
            lease,
            &args,
            19,
            Some(899),
        )
        .unwrap();
        let ceased = child.wait(Duration::from_secs(10)).unwrap();
        assert!(libc::WIFEXITED(ceased.status));
        assert_eq!(libc::WEXITSTATUS(ceased.status), 0);
        let mut raw = [0; 12];
        output.read_exact_at(&mut raw, 0).unwrap();
        assert_eq!(&raw, b"actual-cache");
    }

    fn fixture(command: &str) -> (OwnedChild, File, File, tempfile::TempDir) {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "actual root qualification required"
        );
        let dir = tempfile::tempdir().unwrap();
        let lease = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(dir.path().join("lease"))
            .unwrap();
        lease.try_lock().unwrap();
        let independent = File::options()
            .read(true)
            .write(true)
            .open(dir.path().join("lease"))
            .unwrap();
        let output = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(dir.path().join("out"))
            .unwrap();
        let executable = File::open("/usr/bin/dash").unwrap();
        let args = [
            CString::new("dash").unwrap(),
            CString::new("-c").unwrap(),
            CString::new(command).unwrap(),
        ];
        let borrowed = lease.try_clone().unwrap();
        let child = OwnedChild::launch(
            &executable,
            &[(3, &output), (6, &borrowed)],
            lease,
            &args,
            9,
            None,
        )
        .unwrap();
        (child, output, independent, dir)
    }
    #[test]
    #[ignore = "actual root PID namespace qualification"]
    fn owned_child_positive_wait_retains_same_ofd_and_closed_environment() {
        let (child, output, independent, _dir) = fixture(
            "test \"$$\" = 1 && test -z \"$HOME\" && /usr/bin/flock -n 6 && printf done >&3",
        );
        assert!(independent.try_lock().is_err());
        let stopped = child.wait(Duration::from_secs(10)).unwrap();
        assert!(libc::WIFEXITED(stopped.status));
        assert_eq!(libc::WEXITSTATUS(stopped.status), 0);
        assert!(independent.try_lock().is_err());
        let mut raw = [0; 4];
        output.read_exact_at(&mut raw, 0).unwrap();
        assert_eq!(&raw, b"done");
        drop(stopped.into_lease());
        independent.try_lock().unwrap();
    }
    #[test]
    #[ignore = "actual root PID namespace qualification"]
    fn owned_child_timeout_reaps_namespace_descendants_before_lease_release() {
        let (child, output, independent, _dir) =
            fixture("/usr/bin/sleep 120 & printf ready >&3; wait");
        let pid = child.pid;
        let deadline = Instant::now() + Duration::from_secs(5);
        let descendants = loop {
            let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
                .unwrap_or_default();
            if output.metadata().unwrap().len() == 5 && !children.is_empty() {
                break children;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(independent.try_lock().is_err());
        assert!(child.wait(Duration::from_millis(30)).is_err());
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        for descendant in descendants.split_whitespace() {
            let state = std::fs::read_to_string(format!("/proc/{descendant}/stat"));
            if let Ok(state) = state {
                assert_eq!(
                    state.split(')').nth(1).unwrap().split_whitespace().next(),
                    Some("Z")
                );
            }
        }
        independent.try_lock().unwrap();
    }
    #[test]
    #[ignore = "actual root receiver UID and namespace descriptor map"]
    fn receiver_namespace_keeps_anchor9_and_drops_to_dedicated_identity() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::tempdir().unwrap();
        let output = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join("out"))
            .unwrap();
        let lease = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join("lease"))
            .unwrap();
        lease.try_lock().unwrap();
        let other = File::options()
            .read(true)
            .write(true)
            .open(dir.path().join("lease"))
            .unwrap();
        let executable = File::open("/usr/bin/dash").unwrap();
        let args=[CString::new("dash").unwrap(),CString::new("-c").unwrap(),CString::new("test \"$$\" = 1 && test \"$(/usr/bin/id -u)\" = 899 && test \"$(/usr/bin/id -g)\" = 899 && test \"$(/usr/bin/id -G)\" = 899 && printf actual899 >&9").unwrap()];
        let descriptors = (3..=16).map(|fd| (fd, &output)).collect::<Vec<_>>();
        let child =
            OwnedChild::launch(&executable, &descriptors, lease, &args, 19, Some(899)).unwrap();
        assert!(other.try_lock().is_err());
        let ceased = child.wait(Duration::from_secs(5)).unwrap();
        assert!(libc::WIFEXITED(ceased.status));
        assert_eq!(libc::WEXITSTATUS(ceased.status), 0);
        let mut raw = [0; 9];
        std::os::unix::fs::FileExt::read_exact_at(&output, &mut raw, 0).unwrap();
        assert_eq!(&raw, b"actual899");
        assert!(other.try_lock().is_err());
        drop(ceased);
        other.try_lock().unwrap();
    }
}
