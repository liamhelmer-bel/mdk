#![cfg(unix)]

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

fn try_lock(file: &File) -> std::io::Result<()> {
    // SAFETY: flock is a C POD structure; all relevant fields are set below.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_len = 1;
    // SAFETY: file is live and lock points to an initialized flock.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[test]
fn lock_probe_child() {
    let Some(path) = std::env::var_os("MDK_PRIVATE_LOCK_PATH") else {
        return;
    };
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    let result = try_lock(&file);
    if std::env::var("MDK_PRIVATE_LOCK_EXPECT").unwrap() == "held" {
        let errno = result.unwrap_err().raw_os_error().unwrap();
        assert!(errno == libc::EACCES || errno == libc::EAGAIN);
    } else {
        result.unwrap();
    }
}

fn probe(path: &Path, expected: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "database_tests::lock_probe_child", "--nocapture"])
        .env("MDK_PRIVATE_LOCK_PATH", path)
        .env("MDK_PRIVATE_LOCK_EXPECT", expected)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn permission_hardening_preserves_main_and_all_sidecar_posix_locks() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("test.sqlite");
    let paths: Vec<_> = ["", "-wal", "-shm", "-journal"]
        .iter()
        .map(|suffix| root.path().join(format!("test.sqlite{suffix}")))
        .collect();
    let files: Vec<_> = paths
        .iter()
        .map(|path| {
            let file = crate::create_new_private(path).unwrap();
            file.set_permissions(fs::Permissions::from_mode(0o644))
                .unwrap();
            try_lock(&file).unwrap();
            file
        })
        .collect();
    for path in &paths {
        probe(path, "held");
    }
    crate::ensure_private_db_files(&db).unwrap();
    for path in &paths {
        probe(path, "held");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(files);
    for path in &paths {
        probe(path, "free");
    }
}

#[test]
fn database_and_sidecars_reject_symlinks_without_changing_target() {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::write(&target, b"unchanged").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let db = root.path().join("test.sqlite");
        symlink(&target, root.path().join(format!("test.sqlite{suffix}"))).unwrap();
        assert!(crate::ensure_private_db_files(&db).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

#[test]
fn concurrent_database_creators_publish_one_private_inode_and_clean_staging() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("test.sqlite");
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                crate::ensure_private_db_files(&db).unwrap();
            });
        }
    });
    assert_eq!(
        fs::metadata(&db).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".db-private.")
    }));
    fs::write(&db, b"preserve").unwrap();
    crate::ensure_private_db_files(&db).unwrap();
    assert_eq!(fs::read(&db).unwrap(), b"preserve");
}
