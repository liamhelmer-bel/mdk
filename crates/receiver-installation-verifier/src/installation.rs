//! Shared closed installation-index encoding and independent inventory bounds.
//! This encoding alone is never closure completeness, custody or admission.
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_INDEX: usize = 32 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_FILE: u64 = 256 * 1024 * 1024;
pub const MAX_TREE: u64 = 2 * 1024 * 1024 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Bound,
    Path,
}
type Result<T> = std::result::Result<T, Error>;

fn string(value: &str, out: &mut Vec<u8>) -> Result<()> {
    out.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            ch if ch <= '\u{1f}' => {
                out.extend_from_slice(format!("\\u{:04x}", ch as u32).as_bytes())
            }
            ch => {
                let mut bytes = [0; 4];
                out.extend_from_slice(ch.encode_utf8(&mut bytes).as_bytes());
            }
        }
        if out.len() > MAX_INDEX {
            return Err(Error::Bound);
        }
    }
    out.push(b'"');
    Ok(())
}
fn append(value: &Value, depth: usize, out: &mut Vec<u8>) -> Result<()> {
    if depth > 16 {
        return Err(Error::Bound);
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::String(value) => string(value, out)?,
        Value::Number(value) => {
            if !value.is_i64() && !value.is_u64() {
                return Err(Error::Encoding);
            }
            out.extend_from_slice(value.to_string().as_bytes());
        }
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                append(value, depth + 1, out)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            out.push(b'{');
            let mut pairs: Vec<_> = values.iter().collect();
            pairs.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            for (index, (key, value)) in pairs.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                string(key, out)?;
                out.push(b':');
                append(value, depth + 1, out)?;
            }
            out.push(b'}');
        }
    }
    if out.len() > MAX_INDEX {
        return Err(Error::Bound);
    }
    Ok(())
}
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append(value, 0, &mut out)?;
    Ok(out)
}
/// Re-encoding exact bytes rejects duplicate keys, insignificant whitespace,
/// short escapes, floats, BOM and alternate integer spellings before schema use.
pub fn parse_canonical(raw: &[u8]) -> Result<Value> {
    if raw.is_empty() || raw.len() > MAX_INDEX {
        return Err(Error::Bound);
    }
    let value: Value = serde_json::from_slice(raw).map_err(|_| Error::Encoding)?;
    if canonical(&value)? != raw {
        return Err(Error::Encoding);
    }
    Ok(value)
}
pub fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

/// The closed recipe, not an ingress path, defines which root is walked.
/// This validator also excludes interpreter bytecode/config search selectors.
pub fn relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 240
        || path.split('/').count() > 32
        || path.chars().any(|ch| ch.is_control() || ch == '\\')
    {
        return Err(Error::Path);
    }
    for original in path.split('/') {
        let folded = original.to_ascii_lowercase();
        let part = folded.as_str();
        if part.is_empty()
            || part == "."
            || part == ".."
            || part == "__pycache__"
            || part.ends_with(".pyc")
            || part.ends_with(".pth")
            || part.ends_with("._pth")
            || part == "pyvenv.cfg"
            || part == "sitecustomize"
            || part.starts_with("sitecustomize.")
            || part == "usercustomize"
            || part.starts_with("usercustomize.")
            || part == "pip"
            || part.starts_with("pip-")
        {
            return Err(Error::Path);
        }
    }
    if path.eq_ignore_ascii_case("installation-index.json") {
        return Err(Error::Path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_canonical_shared_grammar() {
        let value = serde_json::json!({"é":"line\n\t\u{1}","z":[1,true,null],"a":"\\\""});
        let raw = canonical(&value).unwrap();
        assert_eq!(
            std::str::from_utf8(&raw).unwrap(),
            "{\"a\":\"\\\\\\\"\",\"z\":[1,true,null],\"é\":\"line\\u000a\\u0009\\u0001\"}"
        );
        assert_eq!(parse_canonical(&raw).unwrap(), value);
        for raw in [
            br#"{"a":1,"a":1}"#.as_slice(),
            br#"{"a":1.0}"#,
            b"{}\n",
            br#"{"a":"\n"}"#,
            br#"{"a":-0}"#,
        ] {
            assert!(parse_canonical(raw).is_err(), "{raw:?}");
        }
    }
    #[test]
    fn installation_paths_refuse_search_selectors_and_escapes() {
        for path in [
            "/a",
            "a/../b",
            "a//b",
            "a\\b",
            "a/__pycache__/x",
            "a/x.pyc",
            "a/python3._pth",
            "a/pyvenv.cfg",
            "a/pip",
            "a/sitecustomize/__init__.py",
            "a/sitecustomize.cpython-313-x86_64-linux-gnu.so",
            "a/usercustomize.so",
            "installation-index.json",
        ] {
            assert!(relative_path(path).is_err(), "{path}");
        }
        relative_path("python/lib/python3.13/unused.py").unwrap();
        let mut value = Value::Null;
        for _ in 0..17 {
            value = Value::Array(vec![value]);
        }
        assert_eq!(canonical(&value), Err(Error::Bound));
    }
}
/// Exact index grammar for the first closed recipe. These types are structural
/// evidence only; neither serde decoding nor hash equality authenticates them.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    schema: String,
    release_identity: String,
    pub(crate) recipe_id: String,
    pub(crate) platform_id: String,
    source_sha256: String,
    lock_sha256: String,
    artifact_sha256: Vec<String>,
    pub(crate) roles: Roles,
    search: Search,
    external: Vec<External>,
    pub(crate) entries: Vec<Value>,
    tree_sha256: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roles {
    receiver: String,
    pub(crate) python: String,
    pub(crate) product_source: String,
    pub(crate) purelib: String,
    python_prefix: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Search {
    path: Vec<String>,
    prefix: String,
    base_prefix: String,
    exec_prefix: String,
    cache_prefix: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct External {
    path: String,
    sha256: String,
    size: u64,
}
pub(crate) fn hash_string(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Index {
    /// Complete read-only structural index for the source-selected recipe checker.
    pub fn as_value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| Error::Encoding)
    }

    /// Structural validation precedes any filesystem/path resolution. Complete
    /// recipe/ELF/platform validation is separately required before invocation.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value = parse_canonical(raw)?;
        let index: Self = serde_json::from_value(value).map_err(|_| Error::Encoding)?;
        if index.schema != "receiver-installation.v1"
            || index.recipe_id.is_empty()
            || index.recipe_id.len() > 128
            || index.platform_id.is_empty()
            || index.platform_id.len() > 128
            || index.release_identity.is_empty()
            || index.release_identity.len() > 256
            || !hash_string(&index.source_sha256)
            || !hash_string(&index.lock_sha256)
            || index.artifact_sha256.is_empty()
            || index.artifact_sha256.len() > 128
            || index.artifact_sha256.iter().any(|h| !hash_string(h))
            || !hash_string(&index.tree_sha256)
            || index.entries.is_empty()
            || index.entries.len() > MAX_ENTRIES
        {
            return Err(Error::Encoding);
        }
        for role in [
            &index.roles.receiver,
            &index.roles.python,
            &index.roles.product_source,
            &index.roles.purelib,
            &index.roles.python_prefix,
        ] {
            relative_path(role)?;
        }
        let mut last = None;
        let mut total = 0u64;
        let mut directories = std::collections::BTreeSet::new();
        let mut all = std::collections::BTreeMap::new();
        let mut folded = std::collections::BTreeSet::new();
        for entry in &index.entries {
            let array = entry.as_array().ok_or(Error::Encoding)?;
            if array.len() != 5 {
                return Err(Error::Encoding);
            }
            let path = array[0].as_str().ok_or(Error::Encoding)?;
            relative_path(path)?;
            if !path.is_ascii()
                || last.is_some_and(|last: &str| last.as_bytes() >= path.as_bytes())
                || !folded.insert(path.to_ascii_lowercase())
            {
                return Err(Error::Path);
            }
            last = Some(path);
            let kind = array[1].as_str().ok_or(Error::Encoding)?;
            let mode = array[2].as_u64().ok_or(Error::Encoding)?;
            let size = array[3].as_u64().ok_or(Error::Encoding)?;
            match kind {
                "directory" if mode == 0o755 && size == 0 && array[4].is_null() => {
                    directories.insert(path);
                }
                "file"
                    if (mode == 0o444 || mode == 0o555)
                        && size <= MAX_FILE
                        && array[4].as_str().is_some_and(hash_string) =>
                {
                    total = total.checked_add(size).ok_or(Error::Bound)?;
                }
                _ => return Err(Error::Encoding),
            }
            all.insert(path, kind);
            if total > MAX_TREE {
                return Err(Error::Bound);
            }
        }
        for path in all.keys() {
            if let Some((parent, _)) = path.rsplit_once('/')
                && !directories.contains(parent)
            {
                return Err(Error::Path);
            }
        }
        for file in [&index.roles.receiver, &index.roles.python] {
            if all.get(file.as_str()) != Some(&"file") {
                return Err(Error::Path);
            }
        }
        for dir in [
            &index.roles.product_source,
            &index.roles.purelib,
            &index.roles.python_prefix,
        ] {
            if !directories.contains(dir.as_str()) {
                return Err(Error::Path);
            }
        }
        if digest(&canonical(&Value::Array(index.entries.clone()))?) != index.tree_sha256 {
            return Err(Error::Encoding);
        }
        if index.search.path.len() > 16 || index.external.len() > 1024 {
            return Err(Error::Bound);
        }
        // First supported recipe stores only installation-relative directories;
        // an empty prefix means the installation root. Cache writes are disabled.
        if index.search.cache_prefix.is_some() {
            return Err(Error::Path);
        }
        let mut paths = std::collections::BTreeSet::new();
        for path in &index.search.path {
            relative_path(path)?;
            if !directories.contains(path.as_str()) || !paths.insert(path) {
                return Err(Error::Path);
            }
        }
        for prefix in [
            &index.search.prefix,
            &index.search.base_prefix,
            &index.search.exec_prefix,
        ] {
            if !prefix.is_empty() {
                relative_path(prefix)?;
                if !directories.contains(prefix.as_str()) {
                    return Err(Error::Path);
                }
            }
        }
        let mut previous_external = None;
        for external in &index.external {
            if previous_external.is_some_and(|previous: &str| previous >= external.path.as_str()) {
                return Err(Error::Path);
            }
            previous_external = Some(external.path.as_str());
            if !external.path.starts_with('/')
                || external.path.len() > 4096
                || external.path.chars().any(char::is_control)
                || external
                    .path
                    .split('/')
                    .skip(1)
                    .any(|p| p.is_empty() || p == "." || p == "..")
                || !hash_string(&external.sha256)
                || external.size > MAX_FILE
            {
                return Err(Error::Path);
            }
        }
        Ok(index)
    }
}

#[cfg(test)]
pub mod index_tests {
    use super::*;
    use std::fs::File;
    pub fn fixture() -> Value {
        let entries = serde_json::json!([
            ["product", "directory", 493, 0, null],
            ["purelib", "directory", 493, 0, null],
            ["python", "directory", 493, 0, null],
            ["python/bin", "directory", 493, 0, null],
            ["python/bin/python", "file", 365, 0, digest(b"")],
            ["receiver", "file", 365, 0, digest(b"")]
        ]);
        serde_json::json!({"schema":"receiver-installation.v1","release_identity":"fixture-only","recipe_id":"fixture","platform_id":"fixture","source_sha256":"a".repeat(64),"lock_sha256":"b".repeat(64),"artifact_sha256":["c".repeat(64)],"roles":{"receiver":"receiver","python":"python/bin/python","product_source":"product","purelib":"purelib","python_prefix":"python"},"search":{"path":[],"prefix":"","base_prefix":"","exec_prefix":"","cache_prefix":null},"external":[],"tree_sha256":digest(&canonical(&entries).unwrap()),"entries":entries})
    }
    #[test]
    fn installation_search_directories_are_closed_and_relative() {
        for (field, value) in [
            ("prefix", serde_json::json!("/tmp/foreign")),
            ("base_prefix", serde_json::json!("../foreign")),
            ("exec_prefix", serde_json::json!("missing")),
            ("cache_prefix", serde_json::json!("python")),
            ("path", serde_json::json!(["/tmp/foreign"])),
            ("path", serde_json::json!(["python", "python"])),
        ] {
            let mut value_index = fixture();
            value_index["search"][field] = value;
            assert!(
                Index::decode(&canonical(&value_index).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut supported = fixture();
        supported["search"]["path"] = serde_json::json!(["product", "purelib"]);
        supported["search"]["prefix"] = serde_json::json!("python");
        Index::decode(&canonical(&supported).unwrap()).unwrap();
    }
    pub fn materialize(path: &std::path::Path, value: &Value, bytes: &[u8]) {
        use std::{fs, os::unix::fs::PermissionsExt};
        for e in value["entries"].as_array().unwrap() {
            let path = path.join(e[0].as_str().unwrap());
            if e[1] == "directory" {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, bytes).unwrap();
            }
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(e[2].as_u64().unwrap() as u32),
            )
            .unwrap();
        }
    }
    fn actual_index(root: &File, mut value: Value) -> Index {
        let entries = inventory_candidate(root).unwrap();
        value["entries"] = Value::Array(entries);
        value["tree_sha256"] = Value::String(digest(&canonical(&value["entries"]).unwrap()));
        Index::decode(&canonical(&value).unwrap()).unwrap()
    }
    #[test]
    #[ignore = "actual whole-tree ELF source inspection, never target execution"]
    fn installation_inspects_unimported_elf_and_refuses_changed_architecture() {
        use std::{fs, os::unix::fs::PermissionsExt};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let root = File::open(temp.path()).unwrap();
        let native = fs::read("/usr/bin/true").unwrap();
        materialize(temp.path(), &fixture(), &native);
        let unused = temp.path().join("purelib/unimported.so");
        fs::write(&unused, &native).unwrap();
        fs::set_permissions(&unused, fs::Permissions::from_mode(0o444)).unwrap();
        let index = actual_index(&root, fixture());
        let objects = index.inspect_elf_objects(&root).unwrap();
        assert_eq!(objects.len(), 3);
        assert!(objects.iter().any(|o| o.path == "purelib/unimported.so"
            && o.dependencies.needed.iter().any(|s| s == "libc.so.6")));
        let mut changed = native;
        changed[18] = 0;
        changed[19] = 0;
        fs::set_permissions(&unused, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&unused, changed).unwrap();
        fs::set_permissions(&unused, fs::Permissions::from_mode(0o444)).unwrap();
        let changed_index = actual_index(&root, fixture()); // hashes are self-consistent
        assert!(changed_index.inspect_elf_objects(&root).is_err()); // ELF policy independently refuses
    }
    #[test]
    #[ignore = "actual root-owned copy, readback and whole-tree drift controls"]
    fn installation_copy_retains_whole_tree_and_refuses_changed_source() {
        use std::{fs, os::unix::fs::PermissionsExt};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        fs::create_dir(&source_path).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o755)).unwrap();
        let source = File::open(&source_path).unwrap();
        let mut value = fixture();
        materialize(&source_path, &value, b"");
        let unused = source_path.join("python/unused.py");
        fs::write(&unused, b"not imported").unwrap();
        fs::set_permissions(&unused, fs::Permissions::from_mode(0o444)).unwrap();
        let entries = inventory_candidate(&source).unwrap();
        value["entries"] = Value::Array(entries.clone());
        value["tree_sha256"] = Value::String(digest(&canonical(&Value::Array(entries)).unwrap()));
        let index = Index::decode(&canonical(&value).unwrap()).unwrap();
        let destination_path = temp.path().join("stage");
        fs::create_dir(&destination_path).unwrap();
        fs::set_permissions(&destination_path, fs::Permissions::from_mode(0o700)).unwrap();
        let destination = File::open(&destination_path).unwrap();
        index.copy_candidate(&source, &destination).unwrap();
        assert_eq!(inventory_candidate(&destination).unwrap(), index.entries);
        assert_eq!(
            fs::read(destination_path.join("python/unused.py")).unwrap(),
            b"not imported"
        );
        assert!(index.copy_candidate(&source, &destination).is_err()); // no adoption/overwrite
        let fresh_path = temp.path().join("fresh");
        fs::create_dir(&fresh_path).unwrap();
        fs::set_permissions(&fresh_path, fs::Permissions::from_mode(0o700)).unwrap();
        let fresh = File::open(&fresh_path).unwrap();
        fs::set_permissions(&unused, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&unused, b"NOT imported").unwrap();
        fs::set_permissions(&unused, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(index.copy_candidate(&source, &fresh).is_err());
        assert_eq!(fs::read_dir(fresh_path).unwrap().count(), 0);
        assert_eq!(
            fs::read(destination_path.join("python/unused.py")).unwrap(),
            b"not imported"
        );
        let raw = canonical(&value).unwrap();
        let index_path = destination_path.join("installation-index.json");
        fs::write(&index_path, &raw).unwrap();
        fs::set_permissions(&index_path, fs::Permissions::from_mode(0o444)).unwrap();
        index.compare_published(&destination, &raw).unwrap();
        assert!(inventory_candidate(&destination).is_err());
        fs::set_permissions(&index_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&index_path, b"{}").unwrap();
        fs::set_permissions(&index_path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(index.compare_published(&destination, &raw).is_err());
        fs::write(&index_path, &raw).unwrap();
        index.compare_published(&destination, &raw).unwrap();
        fs::remove_file(&index_path).unwrap();
        assert!(index.compare_published(&destination, &raw).is_err());
    }
    #[test]
    fn installation_index_structural_decode_is_closed_and_tree_bound() {
        let value = fixture();
        Index::decode(&canonical(&value).unwrap()).unwrap();
        let mut changed = value.clone();
        changed["unknown"] = Value::Bool(true);
        assert!(Index::decode(&canonical(&changed).unwrap()).is_err());
        let mut changed = value.clone();
        changed["entries"][5][4] = Value::String("d".repeat(64));
        assert!(Index::decode(&canonical(&changed).unwrap()).is_err());
        let mut changed = value.clone();
        changed["entries"][5][2] = Value::from(0o4755);
        assert!(Index::decode(&canonical(&changed).unwrap()).is_err());
        let mut changed = value;
        changed["roles"]["python"] = Value::String("outside/bin/python".into());
        assert!(Index::decode(&canonical(&changed).unwrap()).is_err());
    }
}

#[path = "installation_tree.rs"]
mod tree;
pub use tree::{inventory_candidate, ElfObject, ExternalObject};
