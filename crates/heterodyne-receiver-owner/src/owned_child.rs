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
    diagnostic: Option<Diagnostic>,
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

    pub(crate) fn serving(
        executable: &File,
        descriptors: &[(RawFd, &File)],
        lease: File,
    ) -> Result<Self> {
        if descriptors.len() != 14 || !(3..=16).all(|n| descriptors.iter().any(|(fd, _)| *fd == n))
        {
            return Err(Error::Hold);
        }
        Self::launch(
            executable,
            descriptors,
            lease,
            &[CString::new("heterodyne-protected-receiver").unwrap()],
            19,
            Some(899),
        )
    }
    /// Retain the exact lifetime lease until actual PID namespace cessation.
    /// Serving has no automatic restart or effect timeout/adoption path.
    pub(crate) fn wait_serving(mut self) -> Result<(Cessation, Option<String>)> {
        let status = self.reap()?;
        let stage = self.observed_stage();
        Ok((
            Cessation {
                status,
                lease: self.lease.take().ok_or(Error::Hold)?,
            },
            stage,
        ))
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
        // Only fixed receiver entries get bounded stage capture. All raw
        // stderr is discarded; unrelated children retain /dev/null.
        let capture = arguments[0].as_c_str() == c"heterodyne-protected-receiver-enroll"
            || arguments[0].as_c_str() == c"heterodyne-protected-receiver";
        let (diagnostic_reader, diagnostic_writer) = if capture {
            let mut pipe = [-1; 2];
            if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            (Some(unsafe { File::from_raw_fd(pipe[0]) }), unsafe {
                File::from_raw_fd(pipe[1])
            })
        } else {
            (None, null.try_clone()?)
        };
        let diagnostic_writer = duplicate(&diagnostic_writer)?;
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
                for target in 0..=1 {
                    if libc::dup2(null.as_raw_fd(), target) < 0 {
                        libc::_exit(125);
                    }
                }
                if libc::dup2(diagnostic_writer.as_raw_fd(), 2) < 0 {
                    libc::_exit(125);
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
        let mut owned = Self {
            pid: pid as libc::pid_t,
            pidfd: unsafe { File::from_raw_fd(pidfd) },
            lease: Some(lease),
            reaped: false,
            diagnostic: None,
        };
        // Start only after clone: no new Rust thread exists in the forked child.
        // A failed thread creation drops owned and reaps the child before return.
        if let Some(reader) = diagnostic_reader {
            owned.diagnostic = Some(Diagnostic::start(reader)?);
        }
        Ok(owned)
    }

    /// Failure-only observation. Kill/reap the entire owned namespace first,
    /// preserving the original lease until cessation; never interpret a stage
    /// token or an exit status as evidence of enrollment or permission to retry.
    pub(crate) fn failure_diagnostic(&mut self) -> serde_json::Value {
        self.kill();
        let status = self.reap().ok();
        let stage = self.observed_stage();
        serde_json::json!({
            "schema":"heterodyne-owned-child-diagnostic.v1",
            "last_stage": stage,
            "exit_code":status.filter(|s| libc::WIFEXITED(*s)).map(|s| libc::WEXITSTATUS(s)),
            "signal":status.filter(|s| libc::WIFSIGNALED(*s)).map(|s| libc::WTERMSIG(s)),
            "requires_reconciliation":true,"automatic_replay_forbidden":true,
        })
    }
    pub(crate) fn observed_stage(&self) -> Option<String> {
        self.diagnostic.as_ref()?.stage.lock().ok()?.clone()
    }
    fn kill(&self) {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }

    fn reap(&mut self) -> Result<i32> {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.reaped = true;
                if let Some(diagnostic) = &mut self.diagnostic {
                    diagnostic.finish();
                }
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
            self.kill();
            let _ = self.reap();
        }
    }
}

// Continuously drain a blocking child pipe, with bounded parser memory and no
// retained raw stderr. This preserves ordinary write semantics under log floods.
struct Diagnostic {
    stage: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Diagnostic {
    fn start(mut reader: File) -> io::Result<Self> {
        use std::io::Read;
        let stage = std::sync::Arc::new(std::sync::Mutex::new(None));
        let observed = stage.clone();
        let worker = std::thread::Builder::new()
            .name("fresh-diagnostic".into())
            .spawn(move || {
                let mut chunk = [0; 1024];
                let mut line = Vec::with_capacity(128);
                let mut overflow = false;
                loop {
                    let length = match reader.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(length) => length,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    };
                    for byte in &chunk[..length] {
                        if *byte == b'\n' {
                            if !overflow
                                && let Some(value) = diagnostic_stage(&line)
                                && let Ok(mut current) = observed.lock()
                            {
                                retain_diagnostic(&mut current, value);
                            }
                            line.clear();
                            overflow = false;
                        } else if line.len() < 128 && !overflow {
                            line.push(*byte);
                        } else {
                            line.clear();
                            overflow = true;
                        }
                    }
                }
            })?;
        Ok(Self {
            stage,
            worker: Some(worker),
        })
    }
    fn finish(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

// Only source-fixed stage names survive. Discard all other child stderr, including
// error payloads and arbitrary log lines. Diagnostics are not a transport frame.
fn retain_diagnostic(current: &mut Option<String>, value: &str) {
    let specific_failure = current.as_deref().is_some_and(|old| {
        old.starts_with("native-send-")
            || matches!(
                old,
                "native-convergence-refused"
                    | "native-convergence-unexpected-effects"
                    | "native-convergence-not-quiet"
                    | "native-convergence-retained-binding"
                    | "native-convergence-admission-capacity"
            )
    });
    let generic_failure = value.starts_with("serve-failed-") || value == "serve-shutdown-timeout";
    let primary_failure = current
        .as_deref()
        .is_some_and(|old| old.starts_with("serve-failed-"));
    if !(specific_failure && generic_failure
        || primary_failure && value == "serve-shutdown-timeout")
    {
        *current = Some(value.to_owned());
    }
}

fn diagnostic_stage(raw: &[u8]) -> Option<&str> {
    const STAGES: &[&str] = &[
        "entry",
        "profile-read",
        "profile-check",
        "process-hardening",
        "descriptor-claim",
        "binding-check",
        "runtime-create",
        "anchor-check",
        "storage-lease",
        "account-directory",
        "peer-check",
        "secret-read",
        "database-open",
        "sqlcipher-open",
        "engine-create",
        "cache-device",
        "durable-writable",
        "fresh-account",
        "peer-nonce",
        "cache-spool",
        "journal-prepare",
        "intent-check",
        "transport-create",
        "transport-activate",
        "welcome-wait",
        "welcome-binding",
        "welcome-native-join",
        "enrollment-retain",
        "success-frame",
    ];
    const SERVING: &[&str] = &[
        "listener-check",
        "material-check",
        "journal-reopen",
        "sqlcipher-reopen",
        "native-engine",
        "semantic-reopen",
        "group-binding",
        "transport-activate",
        "transport-activate-timeout",
        "transport-subscription-refused",
        "transport-closed",
        "transport-activate-refused",
        "serve-loop",
        "serve-failed-configuration",
        "serve-failed-journal",
        "serve-failed-capacity",
        "serve-failed-latched",
        "serve-failed-engine",
        "serve-failed-changed-state",
        "serve-failed-malformed",
        "serve-shutdown-timeout",
        "native-send-epoch-unsettled",
        "native-send-epoch-mismatch",
        "native-send-storage",
        "native-send-backend",
        "native-send-invalid-payload",
        "native-send-refused",
        "native-convergence-refused",
        "native-convergence-unexpected-effects",
        "native-convergence-not-quiet",
        "native-convergence-not-ready",
        "native-convergence-retained-binding",
        "native-convergence-admission-capacity",
    ];
    if let Some(stage) = std::str::from_utf8(raw)
        .ok()?
        .strip_prefix("serving-stage=")
    {
        return SERVING.contains(&stage).then_some(stage);
    }
    raw.split(|b| *b == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok())
        .filter_map(|line| line.strip_prefix("fresh-stage="))
        .rfind(|stage| STAGES.contains(stage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::FileExt, time::Instant};

    #[test]
    fn diagnostic_discards_error_payloads_and_unknown_tokens() {
        assert_eq!(
            diagnostic_stage(b"secret value\nfresh-stage=database-open\nfresh-stage=not-a-stage\n"),
            Some("database-open")
        );
        assert_eq!(diagnostic_stage(b"fresh-stage=account-secret-123\n"), None);
    }

    #[test]
    fn native_failure_survives_generic_terminal_and_shutdown_stages() {
        let mut current = None;
        for stage in [
            "native-send-epoch-unsettled",
            "serve-failed-latched",
            "serve-shutdown-timeout",
        ] {
            let line = format!("serving-stage={stage}");
            retain_diagnostic(&mut current, diagnostic_stage(line.as_bytes()).unwrap());
        }
        assert_eq!(current.as_deref(), Some("native-send-epoch-unsettled"));
        for primary in [
            "native-convergence-retained-binding",
            "native-convergence-admission-capacity",
        ] {
            current = None;
            for stage in [
                primary,
                "serve-failed-changed-state",
                "serve-shutdown-timeout",
            ] {
                let line = format!("serving-stage={stage}");
                retain_diagnostic(&mut current, diagnostic_stage(line.as_bytes()).unwrap());
            }
            assert_eq!(current.as_deref(), Some(primary));
        }
        current = None;
        for stage in [
            "native-convergence-not-ready",
            "serve-failed-journal",
            "serve-shutdown-timeout",
        ] {
            retain_diagnostic(&mut current, stage);
        }
        assert_eq!(current.as_deref(), Some("serve-failed-journal"));
        assert_eq!(
            diagnostic_stage(b"serving-stage=native-send-private-value"),
            None
        );
    }

    #[test]
    #[ignore = "actual root PID namespace and same-OFD failure custody"]
    fn failed_child_stage_survives_null_stdout_and_is_not_a_success_receipt() {
        let (mut child, _, independent, _dir) =
            fixture("printf 'SECRET VALUE\nfresh-stage=database-open\n' >&2; exit 23");
        crate::supervision::ready(&child.pidfd, Duration::from_secs(5)).unwrap();
        assert!(independent.try_lock().is_err());
        let value = child.failure_diagnostic();
        assert_eq!(value["last_stage"], "database-open");
        assert_eq!(value["exit_code"], 23);
        assert_eq!(value["automatic_replay_forbidden"], true);
        assert!(!value.to_string().contains("SECRET"));
        assert!(
            independent.try_lock().is_err(),
            "failure record still owns lease"
        );
        drop(child);
        independent.try_lock().unwrap();
    }

    #[test]
    #[ignore = "actual root PID namespace and stderr backpressure control"]
    fn diagnostic_drains_large_stderr_and_retains_final_stage() {
        let (mut child, _, independent, _dir) = fixture(
            "head -c 262144 /dev/zero >&2; printf '\nfresh-stage=welcome-native-join\n' >&2; exit 23",
        );
        crate::supervision::ready(&child.pidfd, Duration::from_secs(10)).unwrap();
        let value = child.failure_diagnostic();
        assert_eq!(value["exit_code"], 23);
        assert_eq!(value["last_stage"], "welcome-native-join");
        assert!(independent.try_lock().is_err());
        drop(child);
        independent.try_lock().unwrap();
    }

    #[test]
    fn serving_diagnostics_accept_only_closed_source_stage_names() {
        for stage in [
            "transport-activate-timeout",
            "transport-subscription-refused",
            "transport-closed",
            "transport-activate-refused",
            "serve-failed-configuration",
            "serve-failed-journal",
            "serve-failed-capacity",
            "serve-failed-latched",
            "serve-failed-engine",
            "serve-failed-changed-state",
            "serve-failed-malformed",
            "serve-shutdown-timeout",
        ] {
            assert_eq!(
                diagnostic_stage(format!("serving-stage={stage}").as_bytes()),
                Some(stage)
            );
        }
        assert_eq!(
            diagnostic_stage(b"serving-stage=journal-reopen"),
            Some("journal-reopen")
        );
        assert_eq!(diagnostic_stage(b"serving-stage=secret-value"), None);
        assert_eq!(
            diagnostic_stage(b"serving-stage=journal-reopen extra"),
            None
        );
        assert_eq!(diagnostic_stage(b"arbitrary secret stderr"), None);
    }

    #[test]
    #[ignore = "actual root PID namespace and non-fresh stderr control"]
    fn non_fresh_children_keep_null_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let lease = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(dir.path().join("lease"))
            .unwrap();
        lease.try_lock().unwrap();
        let args = [CString::new("python3").unwrap(), CString::new("-I").unwrap(),
            CString::new("-S").unwrap(),CString::new("-c").unwrap(),
            CString::new("import os; assert os.readlink('/proc/self/fd/2')=='/dev/null'; os.write(2,b'x'*262144)").unwrap()];
        let child = OwnedChild::launch(
            &File::open("/usr/bin/python3.12").unwrap(),
            &[],
            lease,
            &args,
            9,
            None,
        )
        .unwrap();
        assert!(child.diagnostic.is_none());
        let ceased = child.wait(Duration::from_secs(10)).unwrap();
        assert!(libc::WIFEXITED(ceased.status));
        assert_eq!(libc::WEXITSTATUS(ceased.status), 0);
    }

    #[test]
    #[ignore = "actual root PID namespace and built fresh receiver executable"]
    fn real_fresh_entry_failure_is_observed_before_any_native_state() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let path = std::env::var("HETERODYNE_DIAGNOSTIC_FRESH_BINARY").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let input = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(dir.path().join("malformed-profile"))
            .unwrap();
        let lease = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(dir.path().join("lease"))
            .unwrap();
        lease.try_lock().unwrap();
        let descriptors = (3..=16).map(|fd| (fd, &input)).collect::<Vec<_>>();
        let mut child =
            OwnedChild::receiver(&File::open(path).unwrap(), &descriptors, lease, true).unwrap();
        crate::supervision::ready(&child.pidfd, Duration::from_secs(10)).unwrap();
        let value = child.failure_diagnostic();
        assert_eq!(value["last_stage"], "profile-read");
        assert_eq!(value["exit_code"], 2);
        assert_eq!(input.metadata().unwrap().len(), 0);
    }

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
            CString::new("heterodyne-protected-receiver-enroll").unwrap(),
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
    fn serving_wait_reaps_namespace_and_retains_original_ofd() {
        let (child, output, independent, _dir) = fixture("printf served >&3");
        assert!(independent.try_lock().is_err());
        let (ceased, _) = child.wait_serving().unwrap();
        assert!(libc::WIFEXITED(ceased.status));
        assert_eq!(libc::WEXITSTATUS(ceased.status), 0);
        assert!(independent.try_lock().is_err());
        let mut raw = [0; 6];
        output.read_exact_at(&mut raw, 0).unwrap();
        assert_eq!(&raw, b"served");
        drop(ceased);
        independent.try_lock().unwrap();
    }
    #[test]
    #[ignore = "actual root PID namespace and paused failure custody"]
    fn failed_serving_child_retains_stage_and_paused_original_ofd() {
        let (child, output, independent, _dir) =
            fixture("printf 'PRIVATE PAYLOAD\nserving-stage=journal-reopen\n' >&2; exit 2");
        let (ceased, stage) = child.wait_serving().unwrap();
        assert!(libc::WIFEXITED(ceased.status));
        assert_eq!(libc::WEXITSTATUS(ceased.status), 2);
        assert_eq!(stage.as_deref(), Some("journal-reopen"));
        assert!(independent.try_lock().is_err());
        let originals = vec![ceased.into_lease(), output];
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            crate::manual_custody::retain(originals);
        }
        drop(originals);
        // The stopped namespace has been reaped; only the paused supervisor now
        // retains the original OFD. No restart or reconstructed lease is used.
        assert!(independent.try_lock().is_err());
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status));
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
