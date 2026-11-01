//! Verify the fixed copied configuration mount before interpreting ambient
//! loader/NSS/DNS/TLS paths. Mounting is the protected outer bootstrap's job.
use crate::installation::Error;
type Result<T> = std::result::Result<T, Error>;
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

/// The complete directory bytes are independently checked by the exact source
/// inventory. This proves `/etc` is that same installed directory, rather than
/// a caller-asserted similar tree or the host's dynamic resolver symlink.
pub fn require_fixed_etc(root: &File) -> Result<()> {
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c"runtime-etc".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::Path);
    }
    let installed = unsafe { File::from_raw_fd(fd) };
    let expected = installed.metadata().map_err(|_| Error::Path)?;
    let actual = std::fs::symlink_metadata("/etc").map_err(|_| Error::Path)?;
    for m in [&expected, &actual] {
        if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o555 {
            return Err(Error::Path);
        }
    }
    if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
        return Err(Error::Path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::CString, os::unix::fs::PermissionsExt};

    #[test]
    #[ignore = "actual root-owned private mount namespace qualification"]
    fn fixed_etc_namespace_binding() {
        if let Some(path) = std::env::var_os("OIZOH_RUNTIME_ETC_TEST_ROOT") {
            let root = File::open(&path).unwrap();
            assert!(
                require_fixed_etc(&root).is_err(),
                "ambient /etc must refuse"
            );
            let source = CString::new(
                std::path::Path::new(&path)
                    .join("runtime-etc")
                    .as_os_str()
                    .as_encoded_bytes(),
            )
            .unwrap();
            assert_eq!(
                unsafe {
                    libc::mount(
                        source.as_ptr(),
                        c"/etc".as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                },
                0
            );
            assert_eq!(
                unsafe {
                    libc::mount(
                        std::ptr::null(),
                        c"/etc".as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                        std::ptr::null(),
                    )
                },
                0
            );
            require_fixed_etc(&root).unwrap();
            let denied = File::options()
                .write(true)
                .create_new(true)
                .open("/etc/oizoh-unexpected-write")
                .unwrap_err();
            assert_eq!(denied.raw_os_error(), Some(libc::EROFS));
            let other = tempfile::tempdir().unwrap();
            std::fs::create_dir(other.path().join("runtime-etc")).unwrap();
            std::fs::set_permissions(
                other.path().join("runtime-etc"),
                std::fs::Permissions::from_mode(0o555),
            )
            .unwrap();
            assert!(
                require_fixed_etc(&File::open(other.path()).unwrap()).is_err(),
                "another protected directory cannot substitute for the mounted inode"
            );
            return;
        }
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("runtime-etc")).unwrap();
        std::fs::set_permissions(
            root.path().join("runtime-etc"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(
            std::process::Command::new("/usr/bin/unshare")
                .args(["--mount", "--propagation", "private", "--"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "runtime_config::tests::fixed_etc_namespace_binding",
                    "--nocapture"
                ])
                .env("OIZOH_RUNTIME_ETC_TEST_ROOT", root.path())
                .status()
                .unwrap()
                .success()
        );
    }
}
