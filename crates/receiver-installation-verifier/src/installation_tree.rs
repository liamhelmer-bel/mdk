//! Independently walked installation tree, bounded copies and actual ELF scan.
use super::*;

use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    time::{Duration, Instant},
};
#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn identity(file: &File) -> Result<FileIdentity> {
    let m = file.metadata().map_err(|_| Error::Path)?;
    Ok(FileIdentity {
        device: m.dev(),
        inode: m.ino(),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
        links: m.nlink(),
        size: m.size(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
fn no_xattrs(file: &File) -> Result<()> {
    // No ACL/capability/alternate execution selector is supported initially.
    let count = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
    if count != 0 {
        return Err(Error::Path);
    }
    Ok(())
}
fn open_child(directory: &File, name: &str) -> Result<File> {
    let name = CString::new(name).map_err(|_| Error::Path)?;
    let mut before = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            before.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(Error::Path);
    }
    let before = unsafe { before.assume_init() };
    if !matches!(before.st_mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR) {
        return Err(Error::Path);
    }
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(Error::Path);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let after = file.metadata().map_err(|_| Error::Path)?;
    if after.dev() != before.st_dev
        || after.ino() != before.st_ino
        || after.mode() != before.st_mode
    {
        return Err(Error::Path);
    }
    Ok(file)
}
fn mount_id(file: &File) -> Result<u64> {
    let mut stat = std::mem::MaybeUninit::<libc::statx>::uninit();
    let result = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(Error::Path);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(Error::Path);
    }
    Ok(stat.stx_mnt_id)
}
struct Walk {
    entries: Vec<Value>,
    total: u64,
    deadline: Instant,
    mount: u64,
    reserved_index: Option<String>,
    saw_index: bool,
}
impl Walk {
    fn budget(&self) -> Result<()> {
        if Instant::now() >= self.deadline || self.entries.len() >= MAX_ENTRIES {
            Err(Error::Bound)
        } else {
            Ok(())
        }
    }
    fn file_hash(&mut self, file: &mut File, expected: &FileIdentity) -> Result<String> {
        if expected.size > MAX_FILE {
            return Err(Error::Bound);
        }
        self.total = self.total.checked_add(expected.size).ok_or(Error::Bound)?;
        if self.total > MAX_TREE {
            return Err(Error::Bound);
        }
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536];
        let mut size = 0u64;
        loop {
            if Instant::now() >= self.deadline {
                return Err(Error::Bound);
            }
            let count = file.read(&mut buffer).map_err(|_| Error::Path)?;
            if count == 0 {
                break;
            }
            size = size.checked_add(count as u64).ok_or(Error::Bound)?;
            if size > expected.size {
                return Err(Error::Path);
            }
            hash.update(&buffer[..count]);
        }
        if size != expected.size || identity(file)? != *expected {
            return Err(Error::Path);
        }
        Ok(hex::encode(hash.finalize()))
    }
    fn directory(&mut self, directory: &File, prefix: &str) -> Result<()> {
        let before = identity(directory)?;
        if before.mode & libc::S_IFMT != libc::S_IFDIR
            || before.uid != 0
            || before.gid != 0
            || !matches!(before.mode & 0o7777, 0o555 | 0o755)
            || (prefix.is_empty() && before.mode & 0o7777 != 0o755)
            || mount_id(directory)? != self.mount
        {
            return Err(Error::Path);
        }
        no_xattrs(directory)?;
        // /proc/self/fd resolves this retained directory, not an ingress path.
        let mut names = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| Error::Path)?
        {
            if names.len() >= MAX_ENTRIES || Instant::now() >= self.deadline {
                return Err(Error::Bound);
            }
            let name = entry
                .map_err(|_| Error::Path)?
                .file_name()
                .into_string()
                .map_err(|_| Error::Path)?;
            // Initial supported release recipe uses ASCII paths. Refuse unknown
            // Unicode case-fold aliases rather than pretending ASCII lower is full folding.
            if !name.is_ascii() {
                return Err(Error::Path);
            }
            names.push(name);
        }
        names.sort_unstable();
        let mut folded = std::collections::BTreeSet::new();
        if names
            .iter()
            .any(|name| !folded.insert(name.to_ascii_lowercase()))
        {
            return Err(Error::Path);
        }
        for name in names {
            self.budget()?;
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if prefix.is_empty() && name == "installation-index.json" {
                let expected = self.reserved_index.clone().ok_or(Error::Path)?;
                let mut file = open_child(directory, &name)?;
                let before = identity(&file)?;
                if before.uid != 0
                    || before.gid != 0
                    || before.mode & libc::S_IFMT != libc::S_IFREG
                    || before.mode & 0o7777 != 0o444
                    || before.links != 1
                    || before.size > MAX_INDEX as u64
                    || mount_id(&file)? != self.mount
                {
                    return Err(Error::Path);
                }
                no_xattrs(&file)?;
                let mut raw = Vec::new();
                Read::by_ref(&mut file)
                    .take(MAX_INDEX as u64 + 1)
                    .read_to_end(&mut raw)
                    .map_err(|_| Error::Path)?;
                if raw.len() > MAX_INDEX
                    || raw.len() as u64 != before.size
                    || digest(&raw) != expected
                    || identity(&file)? != before
                    || identity(&open_child(directory, &name)?)? != before
                {
                    return Err(Error::Path);
                }
                self.saw_index = true;
                continue;
            }
            relative_path(&path)?;
            let mut file = open_child(directory, &name)?;
            let before = identity(&file)?;
            if before.uid != 0 || before.gid != 0 || mount_id(&file)? != self.mount {
                return Err(Error::Path);
            }
            no_xattrs(&file)?;
            match before.mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    self.entries.push(serde_json::json!([
                        path,
                        "directory",
                        before.mode & 0o7777,
                        0,
                        null
                    ]));
                    self.directory(&file, &path)?;
                }
                libc::S_IFREG => {
                    if before.links != 1 || !matches!(before.mode & 0o7777, 0o444 | 0o555) {
                        return Err(Error::Path);
                    }
                    let hash = self.file_hash(&mut file, &before)?;
                    self.entries.push(serde_json::json!([
                        path,
                        "file",
                        before.mode & 0o7777,
                        before.size,
                        hash
                    ]));
                }
                _ => return Err(Error::Path),
            }
            // Verify the entry still names the same opened inode after hashing.
            if identity(&open_child(directory, &name)?)? != before {
                return Err(Error::Path);
            }
        }
        if identity(directory)? != before {
            return Err(Error::Path);
        }
        Ok(())
    }
}

/// Complete mechanical inventory of a candidate's actual retained tree.
/// It is NOT the closed runtime recipe/platform/ELF/search qualification.
/// The reserved index must not exist yet; verifying published trees is separate.
pub fn inventory_candidate(root: &File) -> Result<Vec<Value>> {
    inventory_until(root, Instant::now() + Duration::from_secs(120))
}
fn inventory_until(root: &File, deadline: Instant) -> Result<Vec<Value>> {
    let mut walk = Walk {
        entries: Vec::new(),
        total: 0,
        deadline: deadline.min(Instant::now() + Duration::from_secs(120)),
        mount: mount_id(root)?,
        reserved_index: None,
        saw_index: false,
    };
    walk.directory(root, "")?;
    walk.entries.sort_unstable_by(|a, b| {
        a[0].as_str()
            .unwrap()
            .as_bytes()
            .cmp(b[0].as_str().unwrap().as_bytes())
    });
    Ok(walk.entries)
}

#[cfg(test)]
mod inventory_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    fn readonly(path: &std::path::Path, bytes: &[u8]) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).ok();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
    }
    #[test]
    #[ignore = "actual disposable root-owned inventory"]
    fn installation_actual_full_walk_hashes_unused_files_and_refuses_aliases() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let stdlib = temp.path().join("stdlib");
        fs::create_dir(&stdlib).unwrap();
        fs::set_permissions(&stdlib, fs::Permissions::from_mode(0o755)).unwrap();
        let unused = stdlib.join("unused.py");
        readonly(&unused, b"never imported\n");
        let root = File::open(temp.path()).unwrap();
        let first = inventory_candidate(&root).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[1][0], "stdlib/unused.py");
        assert_eq!(first[1][4], digest(b"never imported\n"));
        readonly(&unused, b"never IMPORTED\n");
        let changed = inventory_candidate(&root).unwrap();
        assert_ne!(first, changed);
        assert_ne!(first[1][4], changed[1][4]);
        let extra = temp.path().join("extra.py");
        readonly(&extra, b"extra");
        assert_eq!(inventory_candidate(&root).unwrap().len(), 3);
        fs::remove_file(&extra).unwrap();
        let alias = temp.path().join("alias.py");
        fs::hard_link(&unused, &alias).unwrap();
        assert!(inventory_candidate(&root).is_err());
        fs::remove_file(alias).unwrap();
        let link = temp.path().join("link.py");
        symlink(&unused, &link).unwrap();
        assert!(inventory_candidate(&root).is_err());
        fs::remove_file(link).unwrap();
        let bytecode = temp.path().join("unimported.pyc");
        readonly(&bytecode, b"stale bytecode");
        assert!(inventory_candidate(&root).is_err());
        fs::remove_file(bytecode).unwrap();
        let case = stdlib.join("UNUSED.py");
        readonly(&case, b"alias");
        assert!(inventory_candidate(&root).is_err());
        fs::remove_file(case).unwrap();
        assert_eq!(inventory_candidate(&root).unwrap(), changed);
    }
}

fn read_index(root: &File) -> Result<Vec<u8>> {
    let file = open_child(root, "installation-index.json")?;
    let before = identity(&file)?;
    if before.uid != 0
        || before.gid != 0
        || before.mode & libc::S_IFMT != libc::S_IFREG
        || before.mode & 0o7777 != 0o444
        || before.links != 1
        || before.size > MAX_INDEX as u64
        || mount_id(&file)? != mount_id(root)?
    {
        return Err(Error::Path);
    }
    no_xattrs(&file)?;
    let mut raw = Vec::new();
    file.take(MAX_INDEX as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| Error::Path)?;
    let current = open_child(root, "installation-index.json")?;
    if raw.len() > MAX_INDEX || raw.len() as u64 != before.size || identity(&current)? != before {
        return Err(Error::Path);
    }
    Ok(raw)
}
impl Index {
    /// Independent read-only evidence, never genuine publication admission.
    pub fn read_published(root: &File, expected_sha: &str) -> Result<Self> {
        Self::read_published_until(
            root,
            expected_sha,
            Instant::now() + Duration::from_secs(120),
        )
    }
    pub fn read_published_until(
        root: &File,
        expected_sha: &str,
        deadline: Instant,
    ) -> Result<Self> {
        if !hash_string(expected_sha) {
            return Err(Error::Encoding);
        }
        let raw = read_index(root)?;
        if digest(&raw) != expected_sha {
            return Err(Error::Path);
        }
        let index = Index::decode(&raw)?;
        index.compare_published_until(root, &raw, deadline)?;
        Ok(index)
    }
}
impl Index {
    /// Readback of exactly one reserved index plus its complete actual tree.
    /// Still structural/runtime evidence only; caller owns authentic release pins.
    pub fn compare_published(&self, root: &File, index_bytes: &[u8]) -> Result<()> {
        self.compare_published_until(root, index_bytes, Instant::now() + Duration::from_secs(120))
    }
    pub fn compare_published_until(
        &self,
        root: &File,
        index_bytes: &[u8],
        deadline: Instant,
    ) -> Result<()> {
        if canonical(&serde_json::to_value(self).map_err(|_| Error::Encoding)?)? != index_bytes {
            return Err(Error::Encoding);
        }
        let mut walk = Walk {
            entries: Vec::new(),
            total: 0,
            deadline: deadline.min(Instant::now() + Duration::from_secs(120)),
            mount: mount_id(root)?,
            reserved_index: Some(digest(index_bytes)),
            saw_index: false,
        };
        walk.directory(root, "")?;
        walk.entries.sort_unstable_by(|a, b| {
            a[0].as_str()
                .unwrap()
                .as_bytes()
                .cmp(b[0].as_str().unwrap().as_bytes())
        });
        if !walk.saw_index || walk.entries != self.entries {
            return Err(Error::Path);
        }
        Ok(())
    }
    pub fn compare_candidate(&self, root: &File) -> Result<()> {
        self.compare_candidate_until(root, Instant::now() + Duration::from_secs(120))
    }
    pub fn compare_candidate_until(&self, root: &File, deadline: Instant) -> Result<()> {
        if inventory_until(root, deadline)? != self.entries {
            return Err(Error::Path);
        }
        Ok(())
    }
}
/// Open each relative component separately; O_NOFOLLOW on only the final path
/// would leave intermediate directory aliases available during copying.
fn open_relative(root: &File, path: &str) -> Result<File> {
    relative_path(path)?;
    let mut current = root.try_clone().map_err(|_| Error::Path)?;
    for part in path.split('/') {
        current = open_child(&current, part)?;
    }
    Ok(current)
}
fn parent_and_name(root: &File, path: &str) -> Result<(File, CString)> {
    relative_path(path)?;
    let (parent, name) = match path.rsplit_once('/') {
        Some((parent, name)) => (open_relative(root, parent)?, name),
        None => (root.try_clone().map_err(|_| Error::Path)?, path),
    };
    if !parent.metadata().map_err(|_| Error::Path)?.is_dir() {
        return Err(Error::Path);
    }
    Ok((parent, CString::new(name).map_err(|_| Error::Path)?))
}
impl Index {
    /// Mechanical copy into this attempt's newly created root-owned directory.
    /// Caller owns durable intent/staging and authentic recipe admission. An
    /// interrupted copy is never adopted or deleted by this routine.
    pub fn copy_candidate(&self, source: &File, destination: &File) -> Result<()> {
        self.copy_candidate_until(
            source,
            destination,
            Instant::now() + Duration::from_secs(300),
        )
    }
    pub fn copy_candidate_until(
        &self,
        source: &File,
        destination: &File,
        deadline: Instant,
    ) -> Result<()> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(300));
        self.compare_candidate_until(source, deadline)?;
        let before = identity(destination)?;
        if before.mode & libc::S_IFMT != libc::S_IFDIR
            || before.mode & 0o7777 != 0o700
            || before.uid != 0
            || before.gid != 0
            || identity(source)?.device == before.device && identity(source)?.inode == before.inode
            || std::fs::read_dir(format!("/proc/self/fd/{}", destination.as_raw_fd()))
                .map_err(|_| Error::Path)?
                .next()
                .is_some()
        {
            return Err(Error::Path);
        }
        no_xattrs(destination)?;
        for entry in &self.entries {
            if Instant::now() >= deadline {
                return Err(Error::Bound);
            }
            let path = entry[0].as_str().ok_or(Error::Encoding)?;
            let (parent, name) = parent_and_name(destination, path)?;
            if entry[1] == "directory" {
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
                    return Err(Error::Path);
                }
                let directory = open_child(&parent, name.to_str().map_err(|_| Error::Path)?)?;
                if unsafe { libc::fchmod(directory.as_raw_fd(), 0o755) } != 0 {
                    return Err(Error::Path);
                }
            } else {
                let mut input = open_relative(source, path)?;
                let original = identity(&input)?;
                let fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                if fd < 0 {
                    return Err(Error::Path);
                }
                let mut output = unsafe { File::from_raw_fd(fd) };
                let mut hash = Sha256::new();
                let mut total = 0u64;
                let mut buffer = [0; 65536];
                loop {
                    if Instant::now() >= deadline {
                        return Err(Error::Bound);
                    }
                    let n = input.read(&mut buffer).map_err(|_| Error::Path)?;
                    if n == 0 {
                        break;
                    }
                    total = total.checked_add(n as u64).ok_or(Error::Bound)?;
                    if total > entry[3].as_u64().ok_or(Error::Encoding)? {
                        return Err(Error::Bound);
                    }
                    hash.update(&buffer[..n]);
                    output.write_all(&buffer[..n]).map_err(|_| Error::Path)?;
                }
                if total != entry[3].as_u64().ok_or(Error::Encoding)?
                    || hex::encode(hash.finalize()) != entry[4].as_str().ok_or(Error::Encoding)?
                    || identity(&input)? != original
                    || identity(&open_relative(source, path)?)? != original
                {
                    return Err(Error::Path);
                }
                if unsafe {
                    libc::fchmod(
                        output.as_raw_fd(),
                        entry[2].as_u64().ok_or(Error::Encoding)? as libc::mode_t,
                    )
                } != 0
                {
                    return Err(Error::Path);
                }
                output.sync_all().map_err(|_| Error::Path)?;
            }
        }
        // Every directory is synced after its children, including empty ones.
        for entry in self.entries.iter().rev().filter(|e| e[1] == "directory") {
            let directory = open_relative(destination, entry[0].as_str().ok_or(Error::Encoding)?)?;
            let mode = entry[2].as_u64().ok_or(Error::Encoding)? as libc::mode_t;
            if unsafe { libc::fchmod(directory.as_raw_fd(), mode) } != 0 {
                return Err(Error::Path);
            }
            directory.sync_all().map_err(|_| Error::Path)?;
        }
        if unsafe { libc::fchmod(destination.as_raw_fd(), 0o755) } != 0 {
            return Err(Error::Path);
        }
        destination.sync_all().map_err(|_| Error::Path)?;
        self.compare_candidate_until(destination, deadline)?;
        self.compare_candidate_until(source, deadline)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ElfObject {
    pub path: String,
    pub dependencies: crate::elf::Dependencies,
}
impl Index {
    /// Inspect every actual ELF in the complete tree. The fixed qualified
    /// recipe must additionally resolve this graph and pin loader/dlopen/config
    /// resources; an observed graph alone is never a complete runtime contract.
    pub fn inspect_elf_objects(&self, root: &File) -> Result<Vec<ElfObject>> {
        self.inspect_elf_objects_checked(root, None)
    }
    /// Inspect a published tree, retaining and checking its exact reserved index
    /// both before and after reading the executable graph.
    pub fn inspect_published_elf_objects(&self, root: &File) -> Result<Vec<ElfObject>> {
        let index_bytes = read_index(root)?;
        self.inspect_elf_objects_checked(root, Some(&index_bytes))
    }
    fn inspect_elf_objects_checked(
        &self,
        root: &File,
        index: Option<&[u8]>,
    ) -> Result<Vec<ElfObject>> {
        self.compare_elf_tree(root, index)?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut result = Vec::new();
        let mut receiver = false;
        let mut python = false;
        for entry in self.entries.iter().filter(|e| e[1] == "file") {
            if Instant::now() >= deadline {
                return Err(Error::Bound);
            }
            let path = entry[0].as_str().ok_or(Error::Encoding)?;
            let mut file = open_relative(root, path)?;
            let before = identity(&file)?;
            let mut magic = [0; 4];
            let mut count = 0;
            while count < 4 {
                let n = file.read(&mut magic[count..]).map_err(|_| Error::Path)?;
                if n == 0 {
                    break;
                }
                count += n;
            }
            if count == 4 && magic == *b"\x7fELF" {
                let mut raw = magic.to_vec();
                loop {
                    if Instant::now() >= deadline {
                        return Err(Error::Bound);
                    }
                    let mut buffer = [0; 65536];
                    let n = file.read(&mut buffer).map_err(|_| Error::Path)?;
                    if n == 0 {
                        break;
                    }
                    if raw.len().checked_add(n).ok_or(Error::Bound)? > MAX_FILE as usize {
                        return Err(Error::Bound);
                    }
                    raw.extend_from_slice(&buffer[..n]);
                }
                if raw.len() as u64 != entry[3].as_u64().ok_or(Error::Encoding)?
                    || digest(&raw) != entry[4].as_str().ok_or(Error::Encoding)?
                {
                    return Err(Error::Path);
                }
                let dependencies = crate::elf::inspect(&raw).map_err(|_| Error::Encoding)?;
                receiver |= path == self.roles.receiver;
                python |= path == self.roles.python;
                result.push(ElfObject {
                    path: path.into(),
                    dependencies,
                });
            }
            if identity(&file)? != before || identity(&open_relative(root, path)?)? != before {
                return Err(Error::Path);
            }
        }
        if !receiver || !python {
            return Err(Error::Path);
        }
        self.compare_elf_tree(root, index)?;
        Ok(result)
    }
    fn compare_elf_tree(&self, root: &File, index: Option<&[u8]>) -> Result<()> {
        match index {
            Some(bytes) => self.compare_published(root, bytes),
            None => self.compare_candidate(root),
        }
    }
}

#[path = "installation_external.rs"]
mod external;
pub use external::ExternalObject;

#[cfg(test)]
mod special_open_tests {
    use super::*;
    use std::os::unix::fs::FileTypeExt;
    #[test]
    fn special_node_is_refused_by_child_opener() {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifoat(root.as_raw_fd(), c"pipe".as_ptr(), 0o600) },
            0
        );
        assert!(open_child(&root, "pipe").is_err());
        assert!(
            std::fs::symlink_metadata(temp.path().join("pipe"))
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }
}
