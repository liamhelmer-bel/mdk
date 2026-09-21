//! Permission changes must not close I/O descriptors for SQLite-owned inodes.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn prepare(path: &Path) -> io::Result<()> {
    match tighten(path) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    // Closing a file after exposing its final name can cancel locks acquired
    // by another SQLite opener in this process. Close the private staging
    // inode first, then publish without replacing a competing creator.
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let staging = path.with_file_name(format!(
        ".db-private.{}.{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = crate::create_new_private(&staging)?;
    let result = crate::set_handle_private(&file).and_then(|()| file.sync_all());
    drop(file);
    let result = result.and_then(|()| publish(&staging, path));
    let cleanup = fs::remove_file(&staging);
    match result {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // Android's successful rename already consumed staging.
    if let Err(error) = cleanup
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(error);
    }
    tighten(path)
}

fn publish(staging: &Path, path: &Path) -> io::Result<()> {
    #[cfg(target_os = "android")]
    {
        crate::rename_noreplace_with_lock(staging, path)
    }
    #[cfg(not(target_os = "android"))]
    {
        fs::hard_link(staging, path)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn tighten(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // O_PATH pins the inode without opening it for I/O. Closing it does not
    // release POSIX record locks. O_NOFOLLOW pins a symlink itself, which we
    // reject before chmod. /proc/self/fd names this pinned inode even if the
    // original pathname is replaced; never fall back to chmod(original_path).
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database artifact must be a regular file",
        ));
    }
    fs::set_permissions(
        format!("/proc/self/fd/{}", file.as_raw_fd()),
        fs::Permissions::from_mode(crate::PRIVATE_FILE_MODE),
    )
    .map_err(|error| {
        // Missing procfs is not a missing database/optional sidecar.
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "database permission hardening requires procfs",
            )
        } else {
            error
        }
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub(super) fn tighten(path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database artifact must be a regular file",
        ));
    }
    let name = CString::new(path.as_os_str().as_bytes())?;
    // Native no-follow chmod changes mode without opening/closing the inode.
    // A swapped final symlink cannot redirect the operation to its target.
    // SAFETY: name is NUL-terminated and valid for the duration of the call.
    let result = unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            name.as_ptr(),
            crate::PRIVATE_FILE_MODE as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database artifact must be a regular file",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn tighten(path: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "database artifact must be a regular file",
        ));
    }
    Ok(())
}
