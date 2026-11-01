//! Source-fixed watchdogs include preflight separately from native network wait.
//! A timeout is still UNKNOWN, never proof that an external effect did not occur.
use std::{
    fs::File,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};
pub(crate) const CESSATION: Duration = Duration::from_secs(60);
const PREFLIGHT: Duration = Duration::from_secs(600);

pub(crate) fn initialization(deadline_ms: u64, outer: bool) -> Result<Duration, ()> {
    let now = crate::initializer_entry::now()?;
    initialization_at(deadline_ms, now, outer)
}
fn initialization_at(deadline_ms: u64, now: u64, outer: bool) -> Result<Duration, ()> {
    let remaining = deadline_ms.saturating_sub(now);
    if remaining > 600000 {
        return Err(());
    }
    // Child native publication already obeys this SAME absolute deadline.
    // The outer owner must also allow the inner owner's final full reread.
    Ok(Duration::from_millis(remaining)
        + CESSATION
        + if outer {
            PREFLIGHT + CESSATION
        } else {
            Duration::ZERO
        })
}
pub(crate) fn receiver(network_seconds: u64) -> Result<Duration, ()> {
    if !(1..=300).contains(&network_seconds) {
        return Err(());
    }
    // Explicit finite resource watchdog, not a claim of an OS I/O upper bound.
    Ok(PREFLIGHT + Duration::from_secs(network_seconds) + CESSATION)
}
pub(crate) fn ready(file: &File, timeout: Duration) -> Result<(), ()> {
    if timeout.is_zero() || timeout > Duration::from_secs(86400) {
        return Err(());
    }
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(());
        }
        let mut p = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe {
            libc::poll(
                &mut p,
                1,
                remaining.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if n > 0 {
            return if p.revents & libc::POLLIN != 0 {
                Ok(())
            } else {
                Err(())
            };
        }
        if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    #[test]
    fn parent_deadline_includes_child_preflight_and_outer_final_reread() {
        let inner = initialization_at(160000, 100000, false).unwrap();
        let outer = initialization_at(160000, 100000, true).unwrap();
        assert_eq!(inner, Duration::from_secs(120));
        assert!(outer > inner + PREFLIGHT);
        assert_eq!(initialization_at(1, 2, false).unwrap(), CESSATION);
        assert!(initialization_at(700001, 100000, false).is_err());
        assert!(receiver(300).unwrap() > Duration::from_secs(300));
        assert!(receiver(0).is_err());
    }
    #[test]
    fn actual_delayed_preflight_exceeds_old_network_timer_and_still_hands_off() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let file = File::from(std::os::fd::OwnedFd::from(reader));
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            writer.write_all(b"result").unwrap();
        });
        assert!(ready(&file, Duration::from_millis(20)).is_err());
        ready(&file, Duration::from_secs(2)).unwrap();
        thread.join().unwrap();
    }
    #[test]
    fn closed_transferred_endpoint_is_immediately_readable_as_eof() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let file = File::from(std::os::fd::OwnedFd::from(reader));
        drop(writer);
        let started = Instant::now();
        ready(&file, Duration::from_secs(2)).unwrap();
        assert_eq!((&file).read(&mut [0; 1]).unwrap(), 0);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
