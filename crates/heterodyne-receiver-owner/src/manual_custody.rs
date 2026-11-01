//! Hold original OFDs after actual fresh enrollment and complete child cessation.
//! External termination releases custody; it does not authorize a later reopen.
use std::fs::File;

pub(crate) fn retain(files: Vec<File>) -> ! {
    // Keep ownership in this frame. No timeout, file reopen, unlock, automatic
    // replay, or conversion of retained enrollment facts to consent.
    let _originals = files;
    loop {
        unsafe {
            libc::pause();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    #[test]
    fn original_ofd_lock_survives_manual_hold_until_supervisor_ceases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lease");
        let lease = File::create(&path).unwrap();
        lease.try_lock().unwrap();
        let mut pipe = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let originals = vec![lease];
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::write(pipe[1], b"r".as_ptr().cast(), 1);
                libc::close(pipe[1]);
            }
            retain(originals);
        }
        unsafe {
            libc::close(pipe[1]);
        }
        let read = unsafe { File::from_raw_fd(pipe[0]) };
        let mut ready = [0u8];
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), ready.as_mut_ptr().cast(), 1) },
            1
        );
        drop(originals);
        let independent = File::options().read(true).write(true).open(&path).unwrap();
        assert!(independent.try_lock().is_err());
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status));
        independent.try_lock().unwrap();
    }
}
