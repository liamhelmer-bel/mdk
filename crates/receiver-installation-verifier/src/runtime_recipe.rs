//! Fixed deployment recipe constraints over a fully read-back index. This is
//! not source provenance: the owner must independently bind its full normalized
//! source inventory, original distributions, source commit and lock artifacts.
use serde_json::{Value, json};

pub const RECIPE: &str = "cpython-312-product-v1";
pub const PLATFORM: &str = "linux-x86_64-cpython-312-v1";

/// Reject layout/search/distribution widening before any interpreter runs.
/// This function is deliberately separate from complete filesystem hashing and
/// loader closure verification; all three are required at production entry.
pub fn qualify_index(index: &Value) -> Result<(), &'static str> {
    if index["recipe_id"] != RECIPE
        || index["platform_id"] != PLATFORM
        || !cfg!(all(target_os = "linux", target_arch = "x86_64"))
    {
        return Err("unsupported runtime recipe");
    }
    if index["roles"]
        != json!({"receiver":"bin/protected-receiver","python":"python/bin/python3.12","product_source":"product/src","purelib":"purelib","python_prefix":"python"})
        || index["search"]
            != json!({"path":["python/lib/python3.12","python/lib/python3.12/lib-dynload","product/src","purelib"],"prefix":"python","base_prefix":"python","exec_prefix":"python","cache_prefix":null})
    {
        return Err("runtime search changed");
    }
    let entries = index["entries"]
        .as_array()
        .ok_or("missing runtime inventory")?;
    let mut files = std::collections::BTreeMap::new();
    for entry in entries {
        let path = entry[0].as_str().ok_or("invalid runtime path")?;
        let domain = path == "bin"
            || path == "bin/protected-receiver"
            || path == "bin/protected-receiver-enroll"
            || path == "bin/heterodyne-receiver-initialize"
            || path == "bin/heterodyne-receiver-owner-init"
            || path == "python"
            || path == "python/empty-certs"
            || path == "python/bin"
            || path == "python/bin/python3.12"
            || path == "python/lib"
            || path == "python/lib/python312.zip"
            || path == "python/lib/python3.12"
            || (path.starts_with("python/lib/python3.12/")
                && !path.starts_with("python/lib/python3.12/config-")
                && !path.contains("/__pycache__/")
                && !path.ends_with(".pyc")
                && !path.ends_with("/sitecustomize.py")
                && !path.ends_with("/usercustomize.py"))
            || path == "product"
            || path == "product/src"
            || path == "product/src/heterodyne"
            || path.starts_with("product/src/heterodyne/")
            || path == "purelib"
            || path == "purelib/heterodyne"
            || path.starts_with("purelib/heterodyne/")
            || path == "purelib/msgspec"
            || path.starts_with("purelib/msgspec/")
            || path == "purelib/heterodyne_metaharness-0.1.0.dist-info"
            || path.starts_with("purelib/heterodyne_metaharness-0.1.0.dist-info/")
            || path == "purelib/msgspec-0.22.0.dist-info"
            || path.starts_with("purelib/msgspec-0.22.0.dist-info/");
        if !domain {
            return Err("runtime domain widened");
        }
        if entry[1] == "file" {
            if files.insert(path, entry).is_some() {
                return Err("duplicate runtime file");
            }
            if path.ends_with(".so") && !path.ends_with(".cpython-312-x86_64-linux-gnu.so") {
                return Err("unsupported extension ABI");
            }
        }
    }
    for path in [
        "bin/protected-receiver",
        "bin/protected-receiver-enroll",
        "bin/heterodyne-receiver-initialize",
        "bin/heterodyne-receiver-owner-init",
        "python/bin/python3.12",
    ] {
        if files.get(path).is_none_or(|v| v[2] != 0o555) {
            return Err("runtime executable missing");
        }
    }
    for path in [
        "python/lib/python312.zip",
        "python/lib/python3.12/encodings/__init__.py",
        "python/lib/python3.12/ssl.py",
        "python/lib/python3.12/sqlite3/__init__.py",
        "python/lib/python3.12/lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so",
        "python/lib/python3.12/lib-dynload/_sqlite3.cpython-312-x86_64-linux-gnu.so",
        "product/src/heterodyne/__init__.py",
        "product/src/heterodyne/actions/deployment_producer_process.py",
        "product/src/heterodyne/actions/deployment_profile_check.py",
        "purelib/msgspec/__init__.py",
        "purelib/msgspec/_core.cpython-312-x86_64-linux-gnu.so",
        "purelib/heterodyne_metaharness-0.1.0.dist-info/METADATA",
        "purelib/msgspec-0.22.0.dist-info/METADATA",
    ] {
        if !files.contains_key(path) {
            return Err("runtime required file missing");
        }
    }
    let pinned: Value = serde_json::from_str(include_str!("runtime_inventory.json"))
        .map_err(|_| "invalid compiled runtime inventory")?;
    let observed = entries
        .iter()
        .filter(|row| {
            row[0] != "bin"
                && !matches!(
                    row[0].as_str(),
                    Some(
                        "bin/protected-receiver"
                            | "bin/protected-receiver-enroll"
                            | "bin/heterodyne-receiver-initialize"
                            | "bin/heterodyne-receiver-owner-init"
                    )
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    if Value::Array(observed) != pinned["entries"] {
        return Err("incomplete or changed normalized runtime source");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let pinned: Value = serde_json::from_str(include_str!("runtime_inventory.json")).unwrap();
        let mut entries = pinned["entries"].as_array().unwrap().clone();
        entries.push(json!(["bin", "directory", 493, 0, null]));
        for name in [
            "protected-receiver",
            "protected-receiver-enroll",
            "heterodyne-receiver-initialize",
            "heterodyne-receiver-owner-init",
        ] {
            entries.push(json!([
                format!("bin/{name}"),
                "file",
                365,
                1,
                "a".repeat(64)
            ]));
        }
        entries.sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
        json!({"recipe_id":RECIPE,"platform_id":PLATFORM,
        "roles":{"receiver":"bin/protected-receiver","python":"python/bin/python3.12","product_source":"product/src","purelib":"purelib","python_prefix":"python"},
        "search":{"path":["python/lib/python3.12","python/lib/python3.12/lib-dynload","product/src","purelib"],"prefix":"python","base_prefix":"python","exec_prefix":"python","cache_prefix":null},"entries":entries})
    }
    #[test]
    fn complete_compiled_source_map_refuses_missing_changed_or_extra_files() {
        let valid = fixture();
        qualify_index(&valid).unwrap();
        let mut missing = valid.clone();
        missing["entries"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v[0] != "python/lib/python3.12/ssl.py");
        assert!(qualify_index(&missing).is_err());
        let mut changed = valid.clone();
        let rows = changed["entries"].as_array_mut().unwrap();
        rows.iter_mut()
            .find(|v| v[0] == "python/lib/python3.12/ssl.py")
            .unwrap()[4] = json!("b".repeat(64));
        assert!(qualify_index(&changed).is_err());
        let mut extra = valid.clone();
        extra["entries"].as_array_mut().unwrap().push(json!([
            "python/lib/python3.12/new_import.py",
            "file",
            292,
            0,
            "a".repeat(64)
        ]));
        assert!(qualify_index(&extra).is_err());
        let mut config = valid.clone();
        config["entries"].as_array_mut().unwrap().push(json!([
            "python/lib/python3.12/config-3.12-x86_64-linux-gnu/python.o",
            "file",
            292,
            1,
            "a".repeat(64)
        ]));
        assert!(qualify_index(&config).is_err());
        let mut search = valid;
        search["search"]["path"]
            .as_array_mut()
            .unwrap()
            .push(json!("/usr/lib/python3.12"));
        assert!(qualify_index(&search).is_err());
    }
}
