//! Fixed deployment recipe constraints over a fully read-back index. This is
//! not source provenance: the owner must independently bind its full normalized
//! source inventory, original distributions, source commit and lock artifacts.
use serde_json::{Value, json};

pub(crate) const RECIPE: &str = "cpython-312-product-v1";
pub(crate) const PLATFORM: &str = "linux-x86_64-cpython-312-v1";

/// Reject layout/search/distribution widening before any interpreter runs.
/// This function is deliberately separate from complete filesystem hashing and
/// loader closure verification; all three are required at production entry.
pub(crate) fn qualify_index(index: &Value) -> Result<(), &'static str> {
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
            || path == "bin/heterodyne-receiver-initialize"
            || path == "python"
            || path == "python/bin"
            || path == "python/bin/python3.12"
            || path == "python/lib"
            || path == "python/lib/python312.zip"
            || path == "python/lib/python3.12"
            || path.starts_with("python/lib/python3.12/")
            || path == "product"
            || path == "product/src"
            || path == "product/src/heterodyne"
            || path.starts_with("product/src/heterodyne/")
            || path == "purelib"
            || path == "purelib/heterodyne"
            || path.starts_with("purelib/heterodyne/")
            || path == "purelib/msgspec"
            || path.starts_with("purelib/msgspec/")
            || path == "purelib/heterodyne-0.1.0.dist-info"
            || path.starts_with("purelib/heterodyne-0.1.0.dist-info/")
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
        "bin/heterodyne-receiver-initialize",
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
        "purelib/heterodyne-0.1.0.dist-info/METADATA",
        "purelib/msgspec-0.22.0.dist-info/METADATA",
    ] {
        if !files.contains_key(path) {
            return Err("runtime required file missing");
        }
    }
    Ok(())
}
