//! Private owned Product invocation. Output is rendering data, never consent.
use super::{OriginalAsk, ReceiverHold, digest};
use cgka_traits::types::GroupId;
use nostr::base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::PathBuf,
    process::Command,
    time::Duration,
};

#[path = "protected_owned_process.rs"]
mod process;

/// Constructed only by the eventual enrolled protected startup, not deserialized
/// from an operation or exposed to Python. Root/UID/import custody is separate.
pub(super) struct InstalledProducer {
    pub(super) python: PathBuf,
    pub(super) source: PathBuf,
    pub(super) purelib: PathBuf,
    // Exact enrolled immutable interpreter/import closure; not a caller manifest.
    pub(super) closure: Vec<(PathBuf, String)>,
}
/// Exact pair read from the owned authenticated MLS group-context component.
/// Neither a routing index nor a caller profile establishes this relationship.
pub(super) struct GroupBinding {
    native: GroupId,
    transport: [u8; 32],
}
impl GroupBinding {
    pub(super) fn read<S: cgka_traits::storage::StorageProvider + 'static>(
        engine: &crate::Engine<S>,
        native: &GroupId,
        transport: &[u8],
    ) -> Result<Self, ReceiverHold> {
        let group = engine
            .take_mls_group(native)
            .map_err(|_| ReceiverHold::Engine)?
            .ok_or(ReceiverHold::ChangedState)?;
        let routing = crate::app_components::nostr_routing_of_group(&group)
            .map_err(|_| ReceiverHold::ChangedState)?
            .ok_or(ReceiverHold::ChangedState)?;
        if group.group_id().as_slice() != native.as_slice()
            || routing.nostr_group_id.as_slice() != transport
        {
            return Err(ReceiverHold::ChangedState);
        }
        Ok(Self {
            native: native.clone(),
            transport: routing.nostr_group_id,
        })
    }
}

pub(super) struct Inputs {
    pub(super) profile: File,
    pub(super) archive: File,
    pub(super) commit: File,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: String,
    operation_original_sha256: String,
    packet_sha256: String,
    group_hex: String,
    publication_url: String,
    // Exact Target semantics are owned and checked by the pinned Product code.
    targets: serde_json::Value,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Output {
    schema: String,
    operation_original: String,
    operation_original_sha256: String,
    operation_canonical: String,
    packet_sha256: String,
    ask_id: String,
    group_hex: String,
    request_original: String,
    request_sha256: String,
    publication_url: String,
    publication_commit: String,
    publication_path: String,
    published_original_sha256: String,
    card: String,
    cards_sha256: String,
}
#[derive(PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn identity(file: &File) -> Result<Identity, ReceiverHold> {
    let m = file.metadata().map_err(|_| ReceiverHold::Configuration)?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !m.is_file()
        || m.mode() & 0o777 != 0o400
        || m.nlink() != 1
        || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(ReceiverHold::Configuration);
    }
    Ok(Identity {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        size: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
pub(super) fn read_retained(file: &File, limit: u64) -> Result<Vec<u8>, ReceiverHold> {
    let before = identity(file)?;
    if before.size == 0 || before.size > limit {
        return Err(ReceiverHold::Configuration);
    }
    let mut raw = vec![0; usize::try_from(before.size).map_err(|_| ReceiverHold::Configuration)?];
    file.read_exact_at(&mut raw, 0)
        .map_err(|_| ReceiverHold::Configuration)?;
    if before != identity(file)? {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(raw)
}
fn read_profile(file: &File) -> Result<Profile, ReceiverHold> {
    let raw = read_retained(file, 32768)?;
    let value: Profile = serde_json::from_slice(&raw).map_err(|_| ReceiverHold::Malformed)?;
    if value.schema != "heterodyne-owned-card-profile.v1" || !value.targets.is_array() {
        return Err(ReceiverHold::Configuration);
    }
    Ok(value)
}

impl InstalledProducer {
    fn check(&self) -> Result<(), ReceiverHold> {
        if !self.python.is_absolute()
            || !self.source.is_absolute()
            || !self.purelib.is_absolute()
            || self.closure.is_empty()
            || !self.closure.iter().any(|(p, _)| p == &self.python)
            || !self.closure.iter().any(|(p, _)| {
                p == &self
                    .source
                    .join("heterodyne/actions/deployment_producer_process.py")
            })
        {
            return Err(ReceiverHold::Configuration);
        }
        // Immutable directory/complete closure enrollment is an installation
        // prerequisite. These readbacks detect changed pinned files, not custody.
        for (path, expected) in &self.closure {
            let bytes = std::fs::read(path).map_err(|_| ReceiverHold::Configuration)?;
            if digest(&bytes) != *expected {
                return Err(ReceiverHold::ChangedState);
            }
        }
        Ok(())
    }
    pub(super) fn produce(
        &self,
        inputs: Inputs,
        original: &[u8],
        binding: &GroupBinding,
    ) -> Result<OriginalAsk, ReceiverHold> {
        self.check()?;
        let files = [&inputs.profile, &inputs.archive, &inputs.commit];
        let before = files
            .map(identity)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        if before
            .iter()
            .map(|m| (m.dev, m.ino))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 3
        {
            return Err(ReceiverHold::Configuration);
        }
        let profile = read_profile(&inputs.profile)?;
        if digest(original) != profile.operation_original_sha256
            || hex::encode(binding.native.as_slice()) != profile.group_hex
        {
            return Err(ReceiverHold::ChangedState);
        }
        let stdlib = self
            .python
            .parent()
            .and_then(|p| p.parent())
            .ok_or(ReceiverHold::Configuration)?
            .join("lib/python3.12");
        let paths = serde_json::to_string(&[
            &stdlib,
            &stdlib.join("lib-dynload"),
            &self.source,
            &self.purelib,
        ])
        .map_err(|_| ReceiverHold::Configuration)?;
        let bootstrap = format!(
            "import sys; sys.path={paths}; from heterodyne.actions.deployment_producer_process import _entry; sys.exit(_entry())"
        );
        let mut command = Command::new(&self.python);
        command
            .args(["-I", "-S", "-B", "-c", &bootstrap])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C.UTF-8")
            .env("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
            .env(
                "SSL_CERT_DIR",
                stdlib
                    .parent()
                    .and_then(|p| p.parent())
                    .ok_or(ReceiverHold::Configuration)?
                    .join("empty-certs"),
            )
            .current_dir("/");
        let raw = process::run(command, files, original, Duration::from_secs(30))?;
        self.check()?;
        if before
            != files
                .map(identity)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
        {
            return Err(ReceiverHold::ChangedState);
        }
        correlate(&raw, original, binding, &profile)
    }
}
fn decode(value: &str) -> Result<Vec<u8>, ReceiverHold> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| ReceiverHold::Malformed)?;
    if STANDARD.encode(&bytes) != value {
        return Err(ReceiverHold::Malformed);
    }
    Ok(bytes)
}
/// Called only on stdout from the owned fixed child. Private correlation is not
/// an arbitrary authority importer and cannot produce an operator decision.
fn correlate(
    raw: &[u8],
    original: &[u8],
    binding: &GroupBinding,
    profile: &Profile,
) -> Result<OriginalAsk, ReceiverHold> {
    if raw.is_empty() || raw.len() > 256 * 1024 {
        return Err(ReceiverHold::Capacity);
    }
    let value: Output = serde_json::from_slice(raw).map_err(|_| ReceiverHold::Malformed)?;
    let canonical = decode(&value.operation_canonical)?;
    let request = decode(&value.request_original)?;
    let cards = vec![value.card.clone()];
    if value.schema != "heterodyne-owned-card.v1"
        || serde_json::to_vec(&value).map_err(|_| ReceiverHold::Malformed)? != raw
        || decode(&value.operation_original)? != original
        || value.operation_original_sha256 != digest(original)
        || value.operation_original_sha256 != profile.operation_original_sha256
        || value.packet_sha256 != digest(&canonical)
        || value.packet_sha256 != profile.packet_sha256
        || value.published_original_sha256 != value.packet_sha256
        || value.group_hex != hex::encode(binding.native.as_slice())
        || value.group_hex != profile.group_hex
        || value.publication_url != profile.publication_url
        || value.request_sha256 != digest(&request)
        || value.cards_sha256
            != digest(&serde_json::to_vec(&cards).map_err(|_| ReceiverHold::Malformed)?)
        || !super::valid_ask_id(&value.ask_id)
        || value.card.is_empty()
        || value.card.len() > 24000
        || value.publication_commit.len() != 40
        || value.publication_path.is_empty()
        || !value.publication_url.ends_with(&format!(
            "/{}/{}",
            value.publication_commit, value.publication_path
        ))
    {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(OriginalAsk {
        ask_id: value.ask_id,
        expected_group: binding.native.clone(),
        operation: original.to_vec(),
        operation_canonical: canonical,
        original_request: request,
        card_chunks: cards,
    })
}

#[cfg(test)]
pub(super) fn qualification_correspondence_control(
    raw: &[u8],
    native: GroupId,
    transport: [u8; 32],
) -> Result<OriginalAsk, ReceiverHold> {
    // Deliberately constructed matching-domain control, never Engine authority.
    qualification_original(raw, &GroupBinding { native, transport })
}

#[cfg(test)]
pub(super) fn qualification_original(
    raw: &[u8],
    binding: &GroupBinding,
) -> Result<OriginalAsk, ReceiverHold> {
    let value: Output = serde_json::from_slice(raw).unwrap();
    let original = decode(&value.operation_original).unwrap();
    let profile = Profile {
        schema: "heterodyne-owned-card-profile.v1".into(),
        operation_original_sha256: value.operation_original_sha256.clone(),
        packet_sha256: value.packet_sha256.clone(),
        group_hex: value.group_hex.clone(),
        publication_url: value.publication_url.clone(),
        targets: serde_json::json!([]),
    };
    correlate(raw, &original, binding, &profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Output, Profile, Vec<u8>, GroupBinding) {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("protected_owned_fixture.json")).unwrap();
        let output: Output = serde_json::from_value(value["output"].clone()).unwrap();
        let original = decode(&output.operation_original).unwrap();
        let group = GroupBinding {
            native: GroupId::new(hex::decode(&output.group_hex).unwrap()),
            transport: [0x81; 32],
        };
        let profile = Profile {
            schema: "heterodyne-owned-card-profile.v1".into(),
            operation_original_sha256: output.operation_original_sha256.clone(),
            packet_sha256: output.packet_sha256.clone(),
            group_hex: output.group_hex.clone(),
            publication_url: output.publication_url.clone(),
            targets: serde_json::json!([]),
        };
        (output, profile, original, group)
    }
    #[test]
    fn actual_product_fixture_preserves_original_canonical_request_and_card_bytes() {
        // Actual Product producer output under synthetic HTTPS/profile, not runtime custody.
        let (value, profile, original, group) = fixture();
        let raw = serde_json::to_vec(&value).unwrap();
        let wrong_native = GroupBinding {
            native: GroupId::new(vec![0x91; 32]),
            transport: group.transport,
        };
        assert!(matches!(
            correlate(&raw, &original, &wrong_native, &profile),
            Err(ReceiverHold::ChangedState)
        ));
        let ask = correlate(&raw, &original, &group, &profile).unwrap();
        assert_eq!(ask.operation, original);
        assert_eq!(ask.expected_group, group.native);
        assert_ne!(ask.operation, ask.operation_canonical);
        assert_eq!(
            ask.original_request,
            decode(&value.request_original).unwrap()
        );
        assert_eq!(ask.card_chunks, vec![value.card]);
    }
    #[test]
    fn owned_output_refuses_product_routing_group_and_exact_card_tampering() {
        let (mut value, mut profile, original, binding) = fixture();
        // Both domains are32bytes here: field meaning, not length, rejects routing.
        value.group_hex = hex::encode(binding.transport);
        profile.group_hex = value.group_hex.clone();
        assert!(matches!(
            correlate(
                &serde_json::to_vec(&value).unwrap(),
                &original,
                &binding,
                &profile
            ),
            Err(ReceiverHold::ChangedState)
        ));
        let (mut value, profile, original, binding) = fixture();
        value.card.push('!');
        assert!(matches!(
            correlate(
                &serde_json::to_vec(&value).unwrap(),
                &original,
                &binding,
                &profile
            ),
            Err(ReceiverHold::ChangedState)
        ));
    }

    #[test]
    fn owned_output_correlation_refuses_changed_binding_and_noncanonical_bytes() {
        let (mut value, profile, original, group) = fixture();
        value.request_sha256 = "0".repeat(64);
        assert!(matches!(
            correlate(
                &serde_json::to_vec(&value).unwrap(),
                &original,
                &group,
                &profile
            ),
            Err(ReceiverHold::ChangedState)
        ));
        let (value, profile, original, group) = fixture();
        let mut raw = serde_json::to_vec(&value).unwrap();
        raw.push(b'\n');
        assert!(matches!(
            correlate(&raw, &original, &group, &profile),
            Err(ReceiverHold::ChangedState)
        ));
        let mut wrong_original = original.clone();
        wrong_original.push(b' ');
        assert!(matches!(
            correlate(
                &serde_json::to_vec(&value).unwrap(),
                &wrong_original,
                &group,
                &profile
            ),
            Err(ReceiverHold::ChangedState)
        ));
    }
}
