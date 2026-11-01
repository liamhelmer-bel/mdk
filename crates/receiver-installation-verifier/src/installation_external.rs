//! Read-only corroboration of the exact external baseline entries in an index.
//! The protected owner must select the actual OS root and qualified recipe.
//! This reader supplies neither that provenance nor dynamic-loader completeness.
use super::*;

#[derive(Debug)]
pub struct ExternalObject {
    pub path: String,
    pub dependencies: Option<crate::elf::Dependencies>,
}
fn protected(file: &File, directory: bool) -> Result<FileIdentity> {
    let id = identity(file)?;
    let m = file.metadata().map_err(|_| Error::Path)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if m.is_dir() != directory
        || (!directory && !m.is_file())
        || id.uid != 0
        || id.gid != 0
        || id.mode & 0o7022 != 0
        || (!directory && id.links != 1)
        || flags < 0
        || flags & (libc::O_PATH | libc::O_APPEND) != 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(Error::Path);
    }
    no_xattrs(file)?;
    Ok(id)
}
fn open_baseline(root: &File, path: &str) -> Result<File> {
    let mut current = root.try_clone().map_err(|_| Error::Path)?;
    let mut parts = path
        .strip_prefix('/')
        .ok_or(Error::Path)?
        .split('/')
        .peekable();
    while let Some(part) = parts.next() {
        protected(&current, true)?;
        if part.is_empty() || part == "." || part == ".." {
            return Err(Error::Path);
        }
        current = open_child(&current, part)?;
        if parts.peek().is_some() {
            protected(&current, true)?;
        }
    }
    protected(&current, false)?;
    Ok(current)
}
impl Index {
    /// Hash every pinned external file through checked nofollow parents. All
    /// ELF bytes use the same nonexecuting parser as the installed tree. This
    /// does not infer dlopen resources or authenticate a supplied baseline.
    pub fn inspect_external_baseline(&self, os_root: &File) -> Result<Vec<ExternalObject>> {
        let deadline = Instant::now() + Duration::from_secs(120);
        protected(os_root, true)?;
        let mut total = 0u64;
        let mut result = Vec::new();
        for external in &self.external {
            total = total.checked_add(external.size).ok_or(Error::Bound)?;
            if total > MAX_TREE || Instant::now() >= deadline {
                return Err(Error::Bound);
            }
            let mut file = open_baseline(os_root, &external.path)?;
            let before = protected(&file, false)?;
            if before.size != external.size || before.size > MAX_FILE {
                return Err(Error::Path);
            }
            let mut raw = Vec::new();
            let mut hash = Sha256::new();
            let mut size = 0u64;
            loop {
                if Instant::now() >= deadline {
                    return Err(Error::Bound);
                }
                let mut buffer = [0; 65536];
                let n = file.read(&mut buffer).map_err(|_| Error::Path)?;
                if n == 0 {
                    break;
                }
                size = size.checked_add(n as u64).ok_or(Error::Bound)?;
                if size > before.size {
                    return Err(Error::Path);
                }
                hash.update(&buffer[..n]);
                // Bounded raw bytes are retained only for nonexecuting inspection.
                raw.extend_from_slice(&buffer[..n]);
            }
            if size != external.size
                || hex::encode(hash.finalize()) != external.sha256
                || protected(&file, false)? != before
                || protected(&open_baseline(os_root, &external.path)?, false)? != before
            {
                return Err(Error::Path);
            }
            let dependencies = if !raw.starts_with(b"\x7fELF") {
                None
            } else {
                Some(crate::elf::inspect(&raw).map_err(|_| Error::Encoding)?)
            };
            result.push(ExternalObject {
                path: external.path.clone(),
                dependencies,
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod external_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    #[test]
    #[ignore = "actual root-owned disposable baseline descriptor fixture"]
    fn external_baseline_actual_hash_parent_and_alias_controls() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("lib");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("configuration");
        fs::write(&path, b"pinned").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut index =
            Index::decode(&canonical(&super::super::index_tests::fixture()).unwrap()).unwrap();
        index.external = vec![External {
            path: "/lib/configuration".into(),
            sha256: digest(b"pinned"),
            size: 6,
        }];
        let root = File::open(temp.path()).unwrap();
        let entries = index.inspect_external_baseline(&root).unwrap();
        assert_eq!(entries[0].path, "/lib/configuration");
        assert!(entries[0].dependencies.is_none());
        fs::write(&path, b"drifts").unwrap();
        assert!(index.inspect_external_baseline(&root).is_err());
        fs::write(&path, b"pinned").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(index.inspect_external_baseline(&root).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::hard_link(&path, dir.join("alias")).unwrap();
        assert!(index.inspect_external_baseline(&root).is_err());
        fs::remove_file(dir.join("alias")).unwrap();
        fs::rename(&path, dir.join("original")).unwrap();
        symlink("original", &path).unwrap();
        assert!(index.inspect_external_baseline(&root).is_err());
    }
}
