//! Owned host-namespace child. Finite callers supply source-selected verified
//! descriptors; there is no public executable/argv API or namespace transition.
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    time::Duration,
};
type Result<T> = std::result::Result<T, ()>;
pub(crate) struct HostChild {
    pid: i32,
    pidfd: File,
    _lease: File,
    reaped: bool,
}
impl HostChild {
    pub(crate) fn bootstrap(
        executable: &File,
        inputs: &[(i32, &File)],
        lease: File,
    ) -> Result<Self> {
        Self::spawn(
            executable,
            &[CString::new("heterodyne-receiver-bootstrap").map_err(|_| ())?],
            inputs,
            lease,
        )
    }
    pub(crate) fn admission(
        executable: &File,
        python: &str,
        prologue: &str,
        inputs: &[(i32, &File)],
        lease: File,
    ) -> Result<Self> {
        let args = [python, "-I", "-S", "-B", "-c", prologue]
            .map(CString::new)
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| ())?;
        Self::spawn(executable, &args, inputs, lease)
    }
    fn spawn(
        executable: &File,
        args: &[CString],
        inputs: &[(i32, &File)],
        lease: File,
    ) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 || inputs.iter().any(|(n, _)| !(3..=18).contains(n)) {
            return Err(());
        }
        let mut destinations = std::collections::BTreeSet::new();
        if inputs.iter().any(|(n, _)| !destinations.insert(*n)) {
            return Err(());
        }
        let duplicate = |file: &File| -> Result<File> {
            let n = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
            if n < 0 {
                return Err(());
            }
            Ok(unsafe { File::from_raw_fd(n) })
        };
        let exe = duplicate(executable)?;
        let copies = inputs
            .iter()
            .map(|(n, f)| Ok((*n, duplicate(f)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut argv = args.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
        argv.push(std::ptr::null());
        let environment = [std::ptr::null::<libc::c_char>()];
        let parent = unsafe { libc::getpid() };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(());
        }
        if pid == 0 {
            unsafe {
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setpgid(0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
                    || libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                    || libc::dup3(exe.as_raw_fd(), 63, libc::O_CLOEXEC) < 0
                {
                    libc::_exit(125);
                }
                for (n, file) in &copies {
                    if libc::dup2(file.as_raw_fd(), *n) < 0 {
                        libc::_exit(125);
                    }
                }
                for n in 3..63 {
                    if !destinations.contains(&n) {
                        libc::close(n);
                    }
                }
                if libc::syscall(libc::SYS_close_range, 64u32, u32::MAX, 0) < 0 {
                    libc::_exit(125);
                }
                libc::fexecve(63, argv.as_ptr(), environment.as_ptr());
                libc::_exit(125);
            }
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if fd < 0 {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(());
        }
        Ok(Self {
            pid,
            pidfd: unsafe { File::from_raw_fd(fd) },
            _lease: lease,
            reaped: false,
        })
    }
    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }
    pub(crate) fn normal_exit(mut self, timeout: Duration) -> Result<()> {
        crate::supervision::ready(&self.pidfd, timeout)?;
        let mut status = 0;
        loop {
            let n = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if n == self.pid {
                self.reaped = true;
                break;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(());
        }
        Ok(())
    }
}
impl Drop for HostChild {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
                libc::kill(-self.pid, libc::SIGKILL);
            }
            loop {
                let n = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
                if n == self.pid
                    || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn lease() -> (tempfile::NamedTempFile, File, File) {
        let path = tempfile::NamedTempFile::new().unwrap();
        let owned = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.path())
            .unwrap();
        owned.try_lock().unwrap();
        let observer = File::open(path.path()).unwrap();
        (path, owned, observer)
    }

    #[test]
    #[ignore = "actual root host child, pidfd and retained OFD"]
    fn actual_root_host_child_retains_same_ofd_and_exact_credentials() {
        assert_eq!(unsafe { libc::getuid() }, 0);
        let (_path, owned, observer) = lease();
        let (incoming, outgoing) = crate::owner_entry::channel().unwrap();
        crate::initializer_handoff::enable_credentials(&incoming).unwrap();
        let executable = File::open("/usr/bin/python3.12").unwrap();
        let code = "import os,time; assert os.getuid()==0 and os.getgroups()==[]; assert set(os.environ)<= {'LC_CTYPE'}; os.write(3,b'host-child'); time.sleep(0.2)";
        let child = HostChild::admission(&executable, "python3.12", code, &[(3, &outgoing)], owned)
            .unwrap();
        drop(outgoing);
        crate::supervision::ready(&incoming, Duration::from_secs(10)).unwrap();
        assert_eq!(
            crate::host_channel::receive(&incoming, child.pid(), 64, false)
                .unwrap()
                .0,
            b"host-child"
        );
        assert!(observer.try_lock().is_err());
        child.normal_exit(Duration::from_secs(10)).unwrap();
        observer.try_lock().unwrap();
    }

    #[test]
    #[ignore = "actual root host child timeout cessation and failed exec"]
    fn actual_root_host_timeout_and_failed_exec_are_not_success() {
        let (_path, owned, observer) = lease();
        let (mut incoming, outgoing) = crate::owner_entry::channel().unwrap();
        let executable = File::open("/usr/bin/python3.12").unwrap();
        let child = HostChild::admission(
            &executable,
            "python3.12",
            "import os,time; os.write(3,b'x'); time.sleep(60)",
            &[(3, &outgoing)],
            owned,
        )
        .unwrap();
        let pid = child.pid();
        drop(outgoing);
        let mut signal = [0];
        incoming.read_exact(&mut signal).unwrap();
        assert!(observer.try_lock().is_err());
        assert!(child.normal_exit(Duration::from_millis(1)).is_err());
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        observer.try_lock().unwrap();
        let (_path, owned, _observer) = lease();
        let invalid = File::open("/dev/null").unwrap();
        let child = HostChild::bootstrap(&invalid, &[], owned).unwrap();
        assert!(child.normal_exit(Duration::from_secs(5)).is_err());
    }
}
