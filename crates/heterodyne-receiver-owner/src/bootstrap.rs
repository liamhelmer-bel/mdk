//! Finite no-argument root lifecycle. Every create is exclusive: crash leftovers
//! are retained and block automatic restart. No native database is opened here.
use crate::{
    bootstrap_peer::Peer, initializer_entry as input, initializer_handoff as handoff,
    owned_child::OwnedChild,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::Duration,
};
type Result<T> = std::result::Result<T, ()>;
const STATE: &str = "/var/lib/heterodyne/receiver-owner";
fn inherited(n: i32) -> Result<File> {
    if unsafe { libc::fcntl(n, libc::F_GETFD) } < 0 {
        return Err(());
    }
    Ok(unsafe { File::from_raw_fd(n) })
}
fn c(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| ())
}
fn root_dir(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ())?;
    let m = f.metadata().map_err(|_| ())?;
    if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o700 {
        return Err(());
    }
    Ok(f)
}
fn directory(parent: &File, name: &str, uid: u32) -> Result<File> {
    let name = c(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(());
    }
    let n = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if n < 0 {
        return Err(());
    }
    let f = unsafe { File::from_raw_fd(n) };
    if unsafe { libc::fchown(n, uid, uid) } != 0 {
        return Err(());
    }
    f.sync_all().map_err(|_| ())?;
    parent.sync_all().map_err(|_| ())?;
    Ok(f)
}
fn create(parent: &File, name: &str, uid: u32, mode: u32, bytes: &[u8]) -> Result<File> {
    let name = c(name)?;
    let n = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if n < 0 {
        return Err(());
    }
    let mut f = unsafe { File::from_raw_fd(n) };
    f.write_all(bytes).map_err(|_| ())?;
    if unsafe { libc::fchown(n, uid, uid) } != 0 || unsafe { libc::fchmod(n, mode) } != 0 {
        return Err(());
    }
    f.sync_all().map_err(|_| ())?;
    parent.sync_all().map_err(|_| ())?;
    // Profiles are readonly original inodes, never reopened private account data.
    if mode == 0o400 {
        let read = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if read < 0 {
            return Err(());
        }
        let r = unsafe { File::from_raw_fd(read) };
        if r.metadata().map_err(|_| ())?.ino() != f.metadata().map_err(|_| ())?.ino() {
            return Err(());
        }
        Ok(r)
    } else {
        Ok(f)
    }
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    receiver_installation_verifier::installation::canonical(value).map_err(|_| ())
}
fn record(parent: &File, name: &str, value: &Value) -> Result<File> {
    create(parent, name, 0, 0o400, &canonical(value)?)
}
pub(super) fn mount_configuration(
    installation: &receiver_installation_verifier::reference::Installation,
) -> Result<()> {
    if installation.root
        != Path::new("/opt/heterodyne-receiver/releases").join(&installation.index_sha256)
        || !input::hash(&installation.index_sha256, 64)
    {
        return Err(());
    }
    let source = c(installation.root.join("runtime-etc").to_str().ok_or(())?)?;
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
                source.as_ptr(),
                c"/etc".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ) != 0
            || libc::mount(
                std::ptr::null(),
                c"/etc".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                std::ptr::null(),
            ) != 0
        {
            return Err(());
        }
    }
    Ok(())
}
fn positive(child: OwnedChild, timeout: Duration) -> Result<File> {
    let result = child.wait(timeout).map_err(|_| ())?;
    if !libc::WIFEXITED(result.status) || libc::WEXITSTATUS(result.status) != 0 {
        return Err(());
    }
    Ok(result.into_lease())
}
fn frame(raw: &[u8], nonce: &[u8; 32], schema: &str) -> Result<Value> {
    let v = crate::native_frame::read(raw)?;
    if v.get("schema").and_then(Value::as_str) != Some(schema)
        || v.get("nonce_hex").and_then(Value::as_str) != Some(hex::encode(nonce).as_str())
    {
        return Err(());
    }
    Ok(v)
}
/// Initializer input FD3..7; permanent verified-publication inputs FD13,14,15,18.
/// All must be prepared by the retained root launcher, never accepted from an
/// operator JSON command, sandbox mount, or mutable pathname request.
fn retain_process_result(state: &File, response: &[u8], nonce: &[u8; 32]) -> Result<()> {
    frame(response, nonce, "heterodyne-owned-consumed.v3")?;
    create(state, "07-process-result.json", 0, 0o400, response)?;
    Ok(())
}
struct Publication {
    host_channel: File,
    host_nonce: [u8; 32],
    producer: File,
    archive: File,
    commit: File,
    packet: File,
}
impl Publication {
    fn inherited() -> Result<Self> {
        let host_channel = inherited(8)?;
        crate::host_channel::capacity(&host_channel)?;
        Ok(Self {
            host_channel,
            host_nonce: crate::host_channel::read_nonce(&inherited(9)?)?,
            producer: inherited(13)?,
            archive: inherited(14)?,
            commit: inherited(15)?,
            packet: inherited(18)?,
        })
    }
}
/// The fixed owned entry still preflights every publication descriptor before
/// generation. The separate manual entry cannot run the publication branch.
pub(crate) fn entry() -> Result<()> {
    validate_entry()?;
    // Claim original initializer descriptors before consuming the sealed nonce.
    let originals = original_inputs()?;
    run(originals, Some(Publication::inherited()?), None)
}
pub(crate) fn manual_entry() -> Result<()> {
    validate_entry()?;
    refuse_publication_descriptors()?;
    run(original_inputs()?, None, None)
}
fn refuse_publication_descriptors() -> Result<()> {
    for n in [8, 9, 13, 14, 15, 18] {
        if unsafe { libc::fcntl(n, libc::F_GETFD) } >= 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
        {
            return Err(());
        }
    }
    Ok(())
}
fn original_inputs() -> Result<[File; 5]> {
    [3, 4, 5, 6, 7]
        .map(inherited)
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| ())
}
fn validate_entry() -> Result<()> {
    if unsafe { libc::geteuid() } != 0
        || std::env::args_os().count() != 1
        || std::env::vars_os().next().is_some()
    {
        return Err(());
    }
    Ok(())
}
fn run(
    originals: [File; 5],
    publication: Option<Publication>,
    serving: Option<serving::Inputs>,
) -> Result<()> {
    let [original, parent, ledger, lease, expiry] = originals;
    let lm = lease.metadata().map_err(|_| ())?;
    if !lm.is_file()
        || lm.uid() != 0
        || lm.gid() != 0
        || lm.mode() & 0o7777 != 0o600
        || lm.nlink() != 1
    {
        return Err(());
    }
    lease.try_lock().map_err(|_| ())?;
    let raw = input::protected_bytes(&original)?;
    let p = input::profile(&raw)?;
    if p.receiver_uid != 899 || p.consumer_uid != 898 {
        return Err(());
    }
    mount_configuration(&p.installation)?;
    // SQLite resolves /proc/self/fd paths to their filesystem path. The
    // protected host ancestor is deliberately unsearchable by the receiver.
    // Retain the same directory through a private, traversable namespace path.
    let parent = crate::material_mount::bind(&parent, p.receiver_uid).map_err(|_| ())?;
    let verified = p.installation.verify().map_err(|_| ())?;
    cgka_engine::protected_expiry_policy::verify_descriptor(&expiry, &p.expiry_profile_sha256)
        .map_err(|_| ())?;
    let root = root_dir(Path::new(STATE))?;
    let state = directory(&root, &p.storage_generation, 0)?;
    record(
        &state,
        "00-intent.json",
        &json!({"schema":"heterodyne-root-bootstrap-intent.v1","initializer_profile_sha256":hex::encode(Sha256::digest(&raw)),"automatic_replay_forbidden":true}),
    )?;
    let (incoming, outgoing) = crate::owner_entry::channel()?;
    handoff::enable_credentials(&incoming).map_err(|_| ())?;
    let exe = crate::owner_entry::selected(&verified, "heterodyne-receiver-owner-init")?;
    let owner = OwnedChild::owner_init(
        &exe,
        &[
            (3, &original),
            (4, &parent),
            (5, &ledger),
            (6, &lease),
            (7, &expiry),
            (8, &outgoing),
        ],
        lease.try_clone().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    drop(outgoing);
    crate::supervision::ready(
        &incoming,
        crate::supervision::initialization(p.deadline_unix_ms, true)?,
    )?;
    // owner-init forwards only AFTER its dedicated child ceased. Its own
    // credentials are root; nested initializer facts were independently checked.
    let (facts, handles) = handoff::receive(&incoming, owner.pid(), 0).map_err(|_| ())?;
    let _same_root_lease = positive(owner, crate::supervision::CESSATION)?;
    crate::owner_entry::validate_handles(&handles, 899)?;
    if facts.request_sha256 != p.request_sha256
        || facts.storage_generation != p.storage_generation
        || facts.initializer_profile_sha256 != hex::encode(Sha256::digest(&raw))
        || facts.installation_index_sha256 != p.installation.index_sha256
        || facts.expiry_profile_sha256 != p.expiry_profile_sha256
        || facts.expected_welcomer != p.expected_welcomer
        || facts.capability_template != p.capability_template
        || facts.capability_policy_sha256 != p.capability_policy_sha256
    {
        return Err(());
    }
    record(
        &state,
        "01-initialized.json",
        &serde_json::to_value(&facts).map_err(|_| ())?,
    )?;
    let [account, key, seed, _database, storage_lease] = handles;
    let journals = directory(&state, "journal", 899)?;
    let intents = directory(&state, "intent", 899)?;
    let anchors = directory(&state, "anchor", 0)?;
    let cache =
        crate::cache_mount::create(&[&account, &journals, &intents, &anchors]).map_err(|_| ())?;
    // Cache creation cloned the mount namespace; retain the identical directory
    // through its current private mount so SQLite's canonical pathname exists.
    let account = crate::material_mount::current_generation(&account, &p.storage_generation)
        .map_err(|_| ())?;
    let journal = create(&journals, "journal", 899, 0o600, &[])?;
    let intent = create(&intents, "intent", 899, 0o600, &[])?;
    let anchor = create(&anchors, "anchor", 0, 0o600, &[])?;
    let fresh = json!({"schema":"heterodyne-protected-receiver-fresh.v3","receiver_uid":899,"consumer_uid":898,"account":facts.account,"group":p.group,"operators":p.operators,"expected_welcomer":p.expected_welcomer,"storage_generation":p.storage_generation,"key_package_ref":facts.key_package_ref,"endpoints":p.inbox_endpoints,"wait_seconds":p.wait_seconds,"expiry_profile_sha256":p.expiry_profile_sha256,"installation":p.installation,"capability_template":p.capability_template,"capability_policy_sha256":p.capability_policy_sha256});
    let fresh_profile = record(&state, "02-fresh-profile.json", &fresh)?;
    let fresh_sha = hex::encode(Sha256::digest(canonical(&fresh)?));
    let exe = crate::owner_entry::selected(&verified, "protected-receiver-enroll")?;
    let peer = Peer::start().map_err(|_| ())?;
    let nonce = peer.nonce;
    record(
        &state,
        "03-fresh-issued.json",
        &json!({"automatic_replay_forbidden":true}),
    )?;
    let mut child = OwnedChild::receiver(
        &exe,
        &[
            (3, &fresh_profile),
            (4, &key),
            (5, &seed),
            (6, &journal),
            (7, &journals),
            (8, &storage_lease),
            (9, &anchor),
            (10, &anchors),
            (11, &intent),
            (12, &intents),
            (13, &account),
            (14, peer.stream().map_err(|_| ())?),
            (15, &cache),
            (16, &expiry),
        ],
        lease.try_clone().map_err(|_| ())?,
        true,
    )
    .map_err(|_| ())?;
    let response = match crate::supervision::receiver(p.wait_seconds)
        .and_then(|timeout| peer.result(timeout).map_err(|_| ()))
    {
        Ok(response) => response,
        Err(_) => {
            let diagnostic = child.failure_diagnostic();
            record(&state, "03-fresh-failed.json", &diagnostic)?;
            return Err(());
        }
    };
    create(&state, "03-fresh-observed.json", 0, 0o400, &response)?;
    let _ = record(
        &state,
        "03-fresh-stage.json",
        &json!({
            "last_stage":child.observed_stage(), "diagnostic_only":true,
        }),
    );
    let _fresh_cessation = positive(child, crate::supervision::CESSATION)?;
    let enrolled = frame(&response, &nonce, "heterodyne-owned-fresh-enrollment.v3")?;
    if enrolled
        .get("startup_profile_sha256")
        .and_then(Value::as_str)
        != Some(fresh_sha.as_str())
    {
        return Err(());
    }
    let enrollment = enrolled.get("enrollment").ok_or(())?;
    let transport_group = enrolled
        .get("transport_group")
        .and_then(Value::as_array)
        .ok_or(())?;
    if transport_group.len() != 32
        || transport_group
            .iter()
            .any(|v| v.as_u64().is_none_or(|n| n > 255))
    {
        return Err(());
    }
    record(&state, "04-enrolled.json", &enrolled)?;
    if let Some(serving) = serving {
        let _outcome = serving::run(
            &serving,
            &p,
            enrollment,
            transport_group,
            &verified,
            serving::Custody {
                state: &state,
                key: &key,
                seed: &seed,
                journal: &journal,
                journals: &journals,
                storage_lease: &storage_lease,
                anchor: &anchor,
                anchors: &anchors,
                expiry: &expiry,
                cache: &cache,
                account: &account,
                lease: &lease,
            },
        );
        // A serving failure never authorizes replay and must not release the
        // original generation. Keep every original OFD even when writing the
        // bounded failure observation itself failed.
        let mut originals = vec![
            original,
            parent,
            ledger,
            lease,
            expiry,
            root,
            state,
            account,
            key,
            seed,
            _database,
            storage_lease,
            journals,
            intents,
            anchors,
            cache,
            journal,
            intent,
            anchor,
            fresh_profile,
            _same_root_lease,
            _fresh_cessation,
        ];
        originals.extend(serving.into_files());
        crate::manual_custody::retain(originals);
    }
    let Some(Publication {
        host_channel,
        host_nonce,
        producer,
        archive,
        commit,
        packet,
    }) = publication
    else {
        // No permanent child or effect is issued. Keep the ORIGINAL account,
        // storage and root lease OFDs alive after genuine native enrollment.
        // This is an operational custody hold, never an approval or adoption.
        crate::manual_custody::retain(vec![
            original,
            parent,
            ledger,
            lease,
            expiry,
            root,
            state,
            account,
            key,
            seed,
            _database,
            storage_lease,
            journals,
            intents,
            anchors,
            cache,
            journal,
            intent,
            anchor,
            fresh_profile,
            _same_root_lease,
            _fresh_cessation,
        ]);
    };
    let process = json!({"schema":"heterodyne-protected-receiver-process.v3","receiver_uid":899,"consumer_uid":898,"enrollment":enrollment,"endpoints":p.inbox_endpoints,"transport_group":transport_group,"python":verified.python(),"product_source":verified.product_source(),"purelib":verified.purelib(),"installation":p.installation,"wait_seconds":p.wait_seconds});
    let process_profile = record(&state, "05-process-profile.json", &process)?;
    let exe = crate::owner_entry::selected(&verified, "protected-receiver")?;
    let peer = Peer::with_nonce(host_nonce).map_err(|_| ())?;
    let nonce = peer.nonce;
    record(
        &state,
        "06-process-issued.json",
        &json!({"automatic_replay_forbidden":true}),
    )?;
    let child = OwnedChild::receiver(
        &exe,
        &[
            (3, &process_profile),
            (4, &key),
            (5, &seed),
            (6, &journal),
            (7, &journals),
            (8, &storage_lease),
            (9, &anchor),
            (10, &anchors),
            (11, &expiry),
            (12, &cache),
            (13, &producer),
            (14, &archive),
            (15, &commit),
            (16, &account),
            (17, peer.stream().map_err(|_| ())?),
            (18, &packet),
        ],
        lease.try_clone().map_err(|_| ())?,
        false,
    )
    .map_err(|_| ())?;
    let response = peer
        .result(crate::supervision::receiver(p.wait_seconds)?)
        .map_err(|_| ())?;
    create(&state, "06-process-observed.json", 0, 0o400, &response)?;
    let _process_cessation = positive(child, crate::supervision::CESSATION)?;
    retain_process_result(&state, &response, &nonce)?;
    // Only after actual permanent receiver/peer cessation. The host parent also
    // waits for this bootstrap to cease before private admission construction.
    crate::host_channel::send(&host_channel, &response, Some(&process_profile))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_response_requires_exact_nonce_schema_and_canonical_input() {
        let nonce = [7; 32];
        let good=canonical(&json!({"schema":"heterodyne-owned-fresh-enrollment.v3","nonce_hex":hex::encode(nonce)})).unwrap();
        assert!(frame(&good, &nonce, "heterodyne-owned-fresh-enrollment.v3").is_ok());
        assert!(frame(&good, &[8; 32], "heterodyne-owned-fresh-enrollment.v3").is_err());
        assert!(frame(&good, &nonce, "heterodyne-owned-fresh-enrollment-hold.v1").is_err());
        assert!(frame(b"{\"schema\":\"a\",\"schema\":\"b\"}", &nonce, "b").is_err());
    }
    #[test]
    #[ignore = "actual root result-file ownership and exact raw native output"]
    fn final_native_result_retains_exact_bytes_and_refuses_duplicate_or_float() {
        let d = tempfile::tempdir().unwrap();
        let f = File::open(d.path()).unwrap();
        let nonce = [7; 32];
        let raw = format!(
            "{{\"schema\":\"heterodyne-owned-consumed.v3\",\"nonce_hex\":\"{}\",\"message\":\"line\\nvalue\"}}",
            hex::encode(nonce)
        )
        .into_bytes();
        assert!(receiver_installation_verifier::installation::parse_canonical(&raw).is_err());
        let duplicate = format!(
            "{{\"nonce_hex\":\"bad\",\"nonce_hex\":\"{}\"}}",
            hex::encode(nonce)
        );
        assert!(retain_process_result(&f, duplicate.as_bytes(), &nonce).is_err());
        let float = format!("{{\"nonce_hex\":\"{}\",\"value\":1.5}}", hex::encode(nonce));
        assert!(retain_process_result(&f, float.as_bytes(), &nonce).is_err());
        for schema in [
            "heterodyne-owned-consumed-hold.v1",
            "heterodyne-owned-fresh-enrollment.v3",
            "",
        ] {
            let refused =
                serde_json::to_vec(&json!({"schema":schema,"nonce_hex":hex::encode(nonce)}))
                    .unwrap();
            assert!(retain_process_result(&f, &refused, &nonce).is_err());
            assert!(!d.path().join("07-process-result.json").exists());
        }
        assert!(retain_process_result(&f, &raw, &[8; 32]).is_err());
        assert!(!d.path().join("07-process-result.json").exists());
        retain_process_result(&f, &raw, &nonce).unwrap();
        assert_eq!(
            std::fs::read(d.path().join("07-process-result.json")).unwrap(),
            raw
        );
        assert!(retain_process_result(&f, &raw, &nonce).is_err());
    }
    #[test]
    #[ignore = "actual root private exclusive filesystem custody"]
    fn phase_records_never_adopt_or_overwrite_prior_issued_state() {
        let dir = tempfile::tempdir().unwrap();
        let f = File::open(dir.path()).unwrap();
        let first = record(&f, "issued.json", &json!({"phase":"issued"})).unwrap();
        let m = first.metadata().unwrap();
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (0, 0, 0o400));
        assert!(record(&f, "issued.json", &json!({"phase":"complete"})).is_err());
        assert_eq!(
            input::protected_bytes(&first).unwrap(),
            canonical(&json!({"phase":"issued"})).unwrap()
        );
        let state = directory(&f, "generation", 0).unwrap();
        assert!(directory(&f, "generation", 0).is_err());
        assert!(std::fs::read_dir(dir.path()).unwrap().count() == 2);
        drop(state);
    }
}

#[cfg(test)]
mod manual_ingress_tests {
    #[test]
    fn manual_ingress_refuses_each_publication_descriptor_and_accepts_absence() {
        let source = std::fs::File::open("/dev/null").unwrap();
        use std::os::fd::AsRawFd;
        let high = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        assert!(high >= 64);
        let source = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(high) };
        for selected in [
            None,
            Some(8),
            Some(9),
            Some(13),
            Some(14),
            Some(15),
            Some(18),
        ] {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                for n in [8, 9, 13, 14, 15, 18] {
                    unsafe {
                        libc::close(n);
                    }
                }
                if let Some(n) = selected {
                    unsafe {
                        libc::dup2(source.as_raw_fd(), n);
                    }
                }
                let correct = super::refuse_publication_descriptors().is_ok() == selected.is_none();
                unsafe {
                    libc::_exit(if correct { 0 } else { 1 });
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}

#[path = "bootstrap_serving.rs"]
mod serving;
pub(crate) fn serving_entry() -> Result<()> {
    validate_entry()?;
    let originals = original_inputs()?;
    let serving = serving::Inputs::inherited()?;
    run(originals, None, Some(serving))
}
