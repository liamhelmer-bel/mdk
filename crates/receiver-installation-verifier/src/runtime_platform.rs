//! Closed Linux/glibc ELF resolution corroboration. No target ELF is executed.
use crate::elf::Dependencies;
use crate::installation::{Error, ExternalObject, Index};
use std::{
    collections::BTreeMap,
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Error>;
fn word(raw: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        raw.get(at..at + 4)
            .ok_or(Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?,
    ))
}
fn text(raw: &[u8], at: usize, start: usize, end: usize) -> Result<&str> {
    if at < start || at >= end {
        return Err(Error::Encoding);
    }
    let rest = &raw[at..end];
    let len = rest
        .iter()
        .take(4096)
        .position(|b| *b == 0)
        .ok_or(Error::Encoding)?;
    let value = std::str::from_utf8(&rest[..len]).map_err(|_| Error::Encoding)?;
    if value.is_empty() || !value.is_ascii() || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::Encoding);
    }
    Ok(value)
}
/// Only the pinned glibc1.1 little-endian x86-64 cache form is supported.
fn cache(raw: &[u8]) -> Result<BTreeMap<String, Vec<String>>> {
    if raw.len() < 48 || raw.len() > 4 * 1024 * 1024 || &raw[..20] != b"glibc-ld.so.cache1.1" {
        return Err(Error::Encoding);
    }
    let n = word(raw, 20)? as usize;
    let len = word(raw, 24)? as usize;
    let start = 48usize
        .checked_add(n.checked_mul(24).ok_or(Error::Bound)?)
        .ok_or(Error::Bound)?;
    let end = start.checked_add(len).ok_or(Error::Bound)?;
    if n > 100000 || end > raw.len() {
        return Err(Error::Bound);
    }
    let mut result = BTreeMap::<String, Vec<String>>::new();
    for ordinal in 0..n {
        let at = 48 + ordinal * 24;
        let key = text(raw, word(raw, at + 4)? as usize, start, end)?;
        if key.contains('/') {
            return Err(Error::Encoding);
        }
        let path = text(raw, word(raw, at + 8)? as usize, start, end)?;
        // Other architectures are not candidates for this fixed platform.
        if word(raw, at)? != 0x303 {
            continue;
        }
        if word(raw, at + 12)? != 0 || raw.get(at + 16..at + 24).ok_or(Error::Encoding)? != [0; 8] {
            return Err(Error::Encoding); // no hwcap/osversion priority ambiguity
        }
        result.entry(key.into()).or_default().push(path.into());
    }
    Ok(result)
}
fn protected_dir(path: &Path) -> Result<()> {
    let m = std::fs::symlink_metadata(path).map_err(|_| Error::Path)?;
    if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7022 != 0 {
        return Err(Error::Path);
    }
    Ok(())
}
/// Resolve only the fixed Ubuntu merged-/usr aliases and leaf library aliases.
/// Every link and parent is checked, bounded and re-read. The final object must
/// already be independently hashed in the complete external baseline.
fn library_path(path: &str) -> Result<String> {
    let mut pending = PathBuf::from(path);
    for _ in 0..8 {
        if !pending.is_absolute() {
            return Err(Error::Path);
        }
        let mut current = PathBuf::from("/");
        let mut replaced = false;
        let components = pending.components().collect::<Vec<_>>();
        for (index, part) in components.iter().enumerate() {
            let std::path::Component::Normal(name) = part else {
                if matches!(part, std::path::Component::RootDir) {
                    continue;
                } else {
                    return Err(Error::Path);
                }
            };
            protected_dir(&current)?;
            current.push(name);
            let m = std::fs::symlink_metadata(&current).map_err(|_| Error::Path)?;
            if m.file_type().is_symlink() {
                if m.uid() != 0 || m.gid() != 0 {
                    return Err(Error::Path);
                }
                let literal = current.to_str().ok_or(Error::Path)?;
                let target = std::fs::read_link(&current).map_err(|_| Error::Path)?;
                let fixed = match literal {
                    "/lib" => target == Path::new("usr/lib"),
                    "/lib64" => target == Path::new("usr/lib64"),
                    "/usr/lib64/ld-linux-x86-64.so.2" => {
                        target == Path::new("../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
                    }
                    _ => {
                        current.parent() == Some(Path::new("/usr/lib/x86_64-linux-gnu"))
                            && target.components().count() == 1
                            && matches!(
                                target.components().next(),
                                Some(std::path::Component::Normal(_))
                            )
                    }
                };
                if !fixed || std::fs::read_link(&current).map_err(|_| Error::Path)? != target {
                    return Err(Error::Path);
                }
                let mut next = match literal {
                    "/lib" => PathBuf::from("/usr/lib"),
                    "/lib64" => PathBuf::from("/usr/lib64"),
                    "/usr/lib64/ld-linux-x86-64.so.2" => {
                        PathBuf::from("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
                    }
                    _ => current.parent().ok_or(Error::Path)?.join(target),
                };
                for remaining in &components[index + 1..] {
                    next.push(remaining.as_os_str());
                }
                pending = next;
                replaced = true;
                break;
            }
        }
        if !replaced {
            if current.parent() != Some(Path::new("/usr/lib/x86_64-linux-gnu")) {
                return Err(Error::Path);
            }
            return current.to_str().map(str::to_owned).ok_or(Error::Path);
        }
    }
    Err(Error::Bound)
}
fn absent(path: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::Path),
    }
}
fn dependency_set(
    deps: &Dependencies,
    objects: &BTreeMap<&str, &Dependencies>,
    cache: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    if let Some(interpreter) = &deps.interpreter
        && (interpreter != "/lib64/ld-linux-x86-64.so.2"
            || !objects.contains_key(library_path(interpreter)?.as_str()))
    {
        return Err(Error::Path);
    }
    for name in &deps.needed {
        let paths = cache.get(name).ok_or(Error::Path)?;
        let mut selected = None;
        for path in paths {
            let canonical = library_path(path)?;
            let object = objects.get(canonical.as_str()).ok_or(Error::Path)?;
            if object.soname.as_ref() != Some(name)
                || selected.as_ref().is_some_and(|old| old != &canonical)
            {
                return Err(Error::Path);
            }
            selected = Some(canonical);
        }
        if selected.is_none() {
            return Err(Error::Path);
        }
    }
    Ok(())
}
pub fn qualify(index: &Index, root: &File, external: &[ExternalObject]) -> Result<()> {
    // Loader injection and unqualified hwcaps bypasses are unsupported.
    for path in [
        "/etc/ld.so.preload",
        "/usr/lib/x86_64-linux-gnu/glibc-hwcaps",
        "/usr/lib64/glibc-hwcaps",
    ] {
        absent(path)?;
    }
    protected_dir(Path::new("/etc"))?;
    let value = index.as_value()?;
    let expected = value["external"]
        .as_array()
        .ok_or(Error::Encoding)?
        .iter()
        .find(|e| e["path"] == "/etc/ld.so.cache")
        .ok_or(Error::Path)?;
    let raw = std::fs::read("/etc/ld.so.cache").map_err(|_| Error::Path)?;
    if raw.len() as u64 != expected["size"].as_u64().ok_or(Error::Encoding)?
        || crate::installation::digest(&raw)
            != expected["sha256"].as_str().ok_or(Error::Encoding)?
    {
        return Err(Error::Path);
    }
    let cache = cache(&raw)?;
    let objects = external
        .iter()
        .filter_map(|e| e.dependencies.as_ref().map(|d| (e.path.as_str(), d)))
        .collect::<BTreeMap<_, _>>();
    for deps in objects.values() {
        dependency_set(deps, &objects, &cache)?;
    }
    for object in index.inspect_published_elf_objects(root)? {
        dependency_set(&object.dependencies, &objects, &cache)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_cache_is_bounded_and_resolves_fixed_cpython_dependencies() {
        let raw = std::fs::read("/etc/ld.so.cache").unwrap();
        let mapped = cache(&raw).unwrap();
        for name in ["libc.so.6", "libm.so.6", "libssl.so.3"] {
            assert!(mapped.contains_key(name));
        }
        assert_eq!(
            library_path("/lib64/ld-linux-x86-64.so.2").unwrap(),
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
        );
        assert!(library_path("/usr/bin/python3.12").is_err());
        assert!(cache(&raw[..47]).is_err());
        let mut changed = raw;
        changed[0] = b'x';
        assert!(cache(&changed).is_err());
    }
}
