//! Give SQLite a canonical path inside the already private receiver namespace.
//! The original protected host path and exact directory identity stay unchanged.
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(crate) fn bind(parent: &File, uid: u32) -> io::Result<File> {
    let before = parent.metadata()?;
    if unsafe { libc::geteuid() } != 0
        || uid != 899
        || !before.is_dir()
        || before.uid() != uid
        || before.gid() != uid
        || before.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::other("material directory custody"));
    }
    let source_path = std::fs::read_link(format!("/proc/self/fd/{}", parent.as_raw_fd()))?;
    let mountpoint = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open("/mnt")?;
    let m = mountpoint.metadata()?;
    if m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7022 != 0 {
        return Err(io::Error::other("private mountpoint custody"));
    }
    // Called only after bootstrap made mount propagation private. A separate
    // mount namespace here also prevents accidental use from changing host mounts.
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) != 0
            || libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            || libc::mount(
                c"tmpfs".as_ptr(),
                c"/mnt".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"mode=0755,size=1048576".as_ptr().cast(),
            ) != 0
            || libc::mkdir(c"/mnt/heterodyne-receiver-material".as_ptr(), 0o700) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // Reopen in the new mount namespace: a descriptor to a mount from its
    // parent namespace is not a legal Linux bind-mount source.
    let source_fd = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(source_path)?;
    let source_meta = source_fd.metadata()?;
    if (before.dev(), before.ino()) != (source_meta.dev(), source_meta.ino()) {
        return Err(io::Error::other("material source identity"));
    }
    let source = CString::new(format!("/proc/self/fd/{}", source_fd.as_raw_fd())).unwrap();
    if unsafe {
        libc::mount(
            source.as_ptr(),
            c"/mnt/heterodyne-receiver-material".as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mapped = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/mnt/heterodyne-receiver-material")?;
    let after = mapped.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.uid(),
        before.gid(),
        before.mode(),
    ) != (
        after.dev(),
        after.ino(),
        after.uid(),
        after.gid(),
        after.mode(),
    ) {
        return Err(io::Error::other("material mount identity"));
    }
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, process::Command};

    #[test]
    #[ignore = "actual root private mount namespace and receiver UID899"]
    fn sqlcipher_under_protected_ancestor() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        if let Some(kind) = std::env::var_os("OIZOH_MATERIAL_MOUNT_CONTROL") {
            let root =
                std::path::PathBuf::from(std::env::var_os("OIZOH_MATERIAL_MOUNT_ROOT").unwrap());
            let material = root.join("material");
            std::fs::create_dir(&material).unwrap();
            std::fs::set_permissions(&material, std::fs::Permissions::from_mode(0o700)).unwrap();
            let name = CString::new(material.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(name.as_ptr(), 899, 899) }, 0);
            let parent = File::open(&material).unwrap();
            assert!(bind(&parent, 898).is_err());
            let run_before = std::fs::metadata("/run").unwrap();
            let parent = if kind == "bound" {
                bind(&parent, 899).unwrap()
            } else {
                parent
            };
            let run_after = std::fs::metadata("/run").unwrap();
            assert_eq!(
                (run_before.dev(), run_before.ino()),
                (run_after.dev(), run_after.ino())
            );
            assert_eq!(std::fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
            unsafe {
                assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
                assert_eq!(libc::setresgid(899, 899, 899), 0);
                assert_eq!(libc::setresuid(899, 899, 899), 0);
                assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                assert_eq!(libc::prctl(libc::PR_SET_DUMPABLE, 0), 0);
            }
            assert!(
                File::open(&material).is_err(),
                "host ancestor must remain inaccessible"
            );
            let generation =
                crate::generation::Generation::create(&parent, &"a".repeat(64)).unwrap();
            let (database, keys, key) = generation.native_inputs().unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(crate::preparation::prepare(
                &database,
                &key,
                keys,
                &"b".repeat(64),
                vec![cgka_traits::TransportEndpoint(
                    "wss://relay.example.com/".into(),
                )],
            ));
            if kind == "bound" {
                assert!(
                    result.is_ok(),
                    "actual bound SQLCipher/native preparation failed"
                );
                assert!(std::fs::metadata(database).unwrap().len() > 0);
            } else {
                assert!(matches!(result, Err(crate::preparation::Error::Native)));
                assert_eq!(std::fs::metadata(database).unwrap().len(), 0);
            }
            return;
        }
        for kind in ["unbound", "bound"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "material_mount::tests::sqlcipher_under_protected_ancestor",
                    "--ignored",
                    "--nocapture",
                ])
                .env("OIZOH_MATERIAL_MOUNT_CONTROL", kind)
                .env("OIZOH_MATERIAL_MOUNT_ROOT", root.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{kind}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
