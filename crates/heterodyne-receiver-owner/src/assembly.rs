//! Root-only read-only deployment preparation. Output is correlation evidence,
//! never consent. Both commands compose the same production codecs/checks.
use receiver_installation_verifier::{
    installation::{Index, canonical, digest, inventory_candidate, parse_canonical},
    reference::Installation,
    runtime_recipe::{PLATFORM, RECIPE, qualify_index},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
type Result<T> = std::result::Result<T, ()>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    release_identity: String,
    external: Vec<External>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct External {
    path: String,
    sha256: String,
    size: u64,
}
fn index(root: &File, evidence: Value) -> Result<Vec<u8>> {
    let e: Evidence = serde_json::from_value(evidence).map_err(|_| ())?;
    let entries = inventory_candidate(root).map_err(|_| ())?;
    let compiled =
        include_bytes!("../../receiver-installation-verifier/src/runtime_inventory.json");
    let source: Value = serde_json::from_slice(compiled).map_err(|_| ())?;
    let artifacts = entries
        .iter()
        .filter(|row| {
            matches!(
                row[0].as_str(),
                Some(
                    "bin/protected-receiver"
                        | "bin/protected-receiver-enroll"
                        | "bin/heterodyne-receiver-initialize"
                        | "bin/heterodyne-receiver-owner-init"
                )
            )
        })
        .map(|row| row[4].clone())
        .collect::<Vec<_>>();
    let v = json!({"schema":"receiver-installation.v1","release_identity":e.release_identity,
      "recipe_id":RECIPE,"platform_id":PLATFORM,"source_sha256":digest(compiled),
      "lock_sha256":source["uv_lock_sha256"],"artifact_sha256":artifacts,
      "roles":{"receiver":"bin/protected-receiver","python":"python/bin/python3.12","product_source":"product/src","purelib":"purelib","python_prefix":"python"},
      "search":{"path":["python/lib/python3.12","python/lib/python3.12/lib-dynload","product/src","purelib"],"prefix":"python","base_prefix":"python","exec_prefix":"python","cache_prefix":null},
      "external":e.external,"tree_sha256":digest(&canonical(&json!(entries)).map_err(|_|())?),"entries":entries});
    let raw = canonical(&v).map_err(|_| ())?;
    Index::decode(&raw).map_err(|_| ())?;
    qualify_index(&v).map_err(|_| ())?;
    Ok(raw)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    request_sha256: String,
    storage_generation: String,
    group: String,
    operators: Vec<String>,
    expected_welcomer: String,
    inbox_endpoints: Vec<String>,
    key_package_endpoints: Vec<String>,
    minimum_accepted_endpoints: usize,
    deadline_unix_ms: u64,
    wait_seconds: u64,
    expiry_profile_sha256: String,
}
fn profile(installation: Installation, request: Value) -> Result<Vec<u8>> {
    let r: Request = serde_json::from_value(request).map_err(|_| ())?;
    let template = cgka_engine::protected_capability_policy::routing_only_v1();
    let p = crate::initializer_entry::Profile {
        schema: "heterodyne-protected-receiver-initializer.v2".into(),
        request_sha256: r.request_sha256,
        storage_generation: r.storage_generation,
        receiver_uid: 899,
        consumer_uid: 898,
        group: r.group,
        operators: r.operators,
        expected_welcomer: r.expected_welcomer,
        inbox_endpoints: r.inbox_endpoints,
        key_package_endpoints: r.key_package_endpoints,
        minimum_accepted_endpoints: r.minimum_accepted_endpoints,
        deadline_unix_ms: r.deadline_unix_ms,
        wait_seconds: r.wait_seconds,
        expiry_profile_sha256: r.expiry_profile_sha256,
        installation,
        capability_template: template.id().into(),
        capability_policy_sha256: template.policy_sha256(),
    };
    let raw = canonical(&serde_json::to_value(p).map_err(|_| ())?).map_err(|_| ())?;
    crate::initializer_entry::profile(&raw)?;
    Ok(raw)
}
pub(crate) fn entry() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(());
    }
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err(());
    }
    let mut raw = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    if raw.len() > 65536 {
        return Err(());
    }
    let input = parse_canonical(&raw).map_err(|_| ())?;
    let output = match args[1].as_str() {
        "index" => {
            let root = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(&args[2])
                .map_err(|_| ())?;
            index(&root, input)?
        }
        "profile" => {
            let root = Path::new(&args[2]);
            let hash = root.file_name().and_then(|s| s.to_str()).ok_or(())?;
            let installation = Installation {
                root: root.into(),
                index_sha256: hash.into(),
                recipe_id: RECIPE.into(),
                platform_id: PLATFORM.into(),
            };
            installation.check().map_err(|_| ())?;
            crate::bootstrap::mount_configuration(&installation)?;
            installation.verify().map_err(|_| ())?;
            profile(installation, input)?
        }
        _ => return Err(()),
    };
    std::io::stdout().write_all(&output).map_err(|_| ())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_cannot_set_identity_or_template_and_uses_production_validation() {
        let i = Installation {
            root: Path::new("/opt/heterodyne-receiver/releases").join("a".repeat(64)),
            index_sha256: "a".repeat(64),
            recipe_id: RECIPE.into(),
            platform_id: PLATFORM.into(),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let r = json!({"request_sha256":"b".repeat(64),"storage_generation":"c".repeat(64),"group":"d".repeat(32),"operators":["e".repeat(64)],"expected_welcomer":"f".repeat(64),"inbox_endpoints":["wss://relay.example.com"],"key_package_endpoints":["wss://relay.example.com"],"minimum_accepted_endpoints":1,"deadline_unix_ms":now+60000,"wait_seconds":30,"expiry_profile_sha256":"1".repeat(64)});
        let actual = parse_canonical(&profile(i.clone(), r.clone()).unwrap()).unwrap();
        assert_eq!(actual["receiver_uid"], 899);
        assert_eq!(actual["consumer_uid"], 898);
        assert_eq!(actual["capability_template"], "routing-only-v1");
        for field in [
            "receiver_uid",
            "consumer_uid",
            "installation",
            "capability_template",
        ] {
            let mut changed = r.clone();
            changed[field] = json!("attacker");
            assert!(profile(i.clone(), changed).is_err());
        }
        let mut expired = r;
        expired["deadline_unix_ms"] = json!(0);
        assert!(profile(i, expired).is_err());
    }
}
