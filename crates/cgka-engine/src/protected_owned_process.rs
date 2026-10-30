//! Finite private Product child mechanics. This is not a custody opener.
use super::ReceiverHold;
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: usize = 256 * 1024;
const INPUT_LIMIT: usize = 32768;

struct ChildGuard {
    child: Child,
    group: i32,
    reaped: bool,
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // The pinned Product producer does not detach descendants. Group teardown
        // also closes inherited stdout on cancellation/failure; always reap child.
        if !self.reaped {
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn nonblocking(fd: i32) -> Result<(), ReceiverHold> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ReceiverHold::Engine);
    }
    Ok(())
}
fn duplicate(file: &File) -> Result<File, ReceiverHold> {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    if fd < 0 {
        return Err(ReceiverHold::Engine);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// All selectors come from the private installed owner, never packet/stdin data.
/// `command` is assembled only by that owner; production exposes no command API.
pub(super) fn run(
    mut command: Command,
    files: [&File; 3],
    original: &[u8],
    budget: Duration,
) -> Result<Vec<u8>, ReceiverHold> {
    if original.is_empty() || original.len() > INPUT_LIMIT || budget.is_zero() {
        return Err(ReceiverHold::Configuration);
    }
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or(ReceiverHold::Configuration)?;
    let copied = [
        duplicate(files[0])?,
        duplicate(files[1])?,
        duplicate(files[2])?,
    ];
    let fds = copied.each_ref().map(AsRawFd::as_raw_fd);
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            for (fd, slot) in fds.into_iter().zip(3..=5) {
                if libc::dup2(fd, slot) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Preserve only stdio and fixed producer inputs across exec. Do not
            // inherit engine keys, journal, anchor, SQLite or consumer descriptors.
            if libc::syscall(
                libc::SYS_close_range,
                6u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|_| ReceiverHold::Engine)?;
    let group = i32::try_from(child.id()).map_err(|_| ReceiverHold::Engine)?;
    let mut guard = ChildGuard {
        child,
        group,
        reaped: false,
    };
    let input = guard.child.stdin.take().ok_or(ReceiverHold::Engine)?;
    let mut output = guard.child.stdout.take().ok_or(ReceiverHold::Engine)?;
    nonblocking(input.as_raw_fd())?;
    nonblocking(output.as_raw_fd())?;
    let mut written = 0;
    let mut bytes = Vec::new();
    let mut eof = false;
    let mut input = Some(input);
    loop {
        if Instant::now() >= deadline {
            return Err(ReceiverHold::Engine);
        }
        if let Some(pipe) = input.as_mut() {
            match pipe.write(&original[written..]) {
                Ok(0) => return Err(ReceiverHold::Engine),
                Ok(n) => written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(ReceiverHold::Engine),
            }
            if written == original.len() {
                input = None;
            }
        }
        let mut buffer = [0; 8192];
        if !eof {
            match output.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(n) => {
                    if n > OUTPUT_LIMIT.saturating_sub(bytes.len()) {
                        return Err(ReceiverHold::Capacity);
                    }
                    bytes.extend_from_slice(&buffer[..n]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(ReceiverHold::Engine),
            }
        }
        // Observe exit without reaping: PGID remains reserved until teardown.
        // Kill the trusted producer group before wait, including pipe-holding
        // descendants. Never signal a group after its leader has been reaped.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                guard.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } < 0
        {
            return Err(ReceiverHold::Engine);
        }
        if unsafe { info.si_pid() } != 0 && eof {
            unsafe {
                libc::kill(-guard.group, libc::SIGKILL);
            }
            let status = guard.child.wait().map_err(|_| ReceiverHold::Engine)?;
            guard.reaped = true;
            if status.success() && written == original.len() && !bytes.is_empty() {
                return Ok(bytes);
            }
            return Err(ReceiverHold::Engine);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn python(script: &str) -> Command {
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-I", "-S", "-B", "-c", script]).env_clear();
        command
    }
    #[test]
    fn owned_child_gets_only_fixed_inputs_and_original_stdin() {
        let mut files = [
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
        ];
        for (f, content) in files
            .iter_mut()
            .zip([b"profile", b"archive".as_slice(), b"commit"])
        {
            f.write_all(content).unwrap();
        }
        // Deliberately non-CLOEXEC sentinel; the owner must close it at exec.
        let sentinel = tempfile::tempfile().unwrap();
        let fd = unsafe { libc::fcntl(sentinel.as_raw_fd(), libc::F_DUPFD, 200) };
        assert!(fd >= 200);
        let retained = unsafe { File::from_raw_fd(fd) };
        let script = format!(
            "import os,sys; assert os.pread(3,7,0)==b'profile'; assert os.pread(4,7,0)==b'archive'; assert os.pread(5,6,0)==b'commit'; assert not os.path.exists('/proc/self/fd/{}'); sys.stdout.buffer.write(sys.stdin.buffer.read())",
            retained.as_raw_fd()
        );
        assert_eq!(
            run(
                python(&script),
                files.each_ref(),
                b"original bytes",
                Duration::from_secs(3)
            )
            .unwrap(),
            b"original bytes"
        );
        assert!(retained.metadata().is_ok());
    }
    #[test]
    fn owned_child_deadline_reaps_actual_process() {
        let files = [
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
        ];
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("child-pid");
        let script = format!(
            "import os,time; open({:?},'w').write(str(os.getpid())); time.sleep(10)",
            path.to_str().unwrap()
        );
        let started = Instant::now();
        assert!(matches!(
            run(
                python(&script),
                files.each_ref(),
                b"original",
                Duration::from_secs(2)
            ),
            Err(ReceiverHold::Engine)
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        let Ok(raw) = std::fs::read_to_string(path) else {
            return;
        };
        let pid: i32 = raw.parse().unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
    #[test]
    fn owned_child_refuses_oversize_output_and_nonzero_exit() {
        let files = [
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
            tempfile::tempfile().unwrap(),
        ];
        assert!(matches!(
            run(
                python("import sys; sys.stdout.buffer.write(b'x'*300000)"),
                files.each_ref(),
                b"original",
                Duration::from_secs(3)
            ),
            Err(ReceiverHold::Capacity)
        ));
        assert!(matches!(
            run(
                python("import sys; sys.exit(2)"),
                files.each_ref(),
                b"original",
                Duration::from_secs(3)
            ),
            Err(ReceiverHold::Engine)
        ));
    }
}
