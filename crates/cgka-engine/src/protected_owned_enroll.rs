//! Fresh-only live Welcome composition. Descriptor publisher/custody is not installed.
use super::*;
use crate::protected_join::{JoinConstraint, JoinEvidence, JoinIntent};
use crate::protected_receiver::ReceiverJournal;
use cgka_traits::TransportEnvelope;

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
#[serde(deny_unknown_fields)]
struct FreshProfile {
    schema: String,
    receiver_uid: u32,
    consumer_uid: u32,
    account: String,
    group: String,
    operators: Vec<String>,
    expected_welcomer: String,
    storage_generation: String,
    // Exact native KeyPackageRef selected by this fresh enrollment, not the
    // outer Nostr event id. Historical invitations for other packages refuse.
    key_package_ref: String,
    endpoints: Vec<TransportEndpoint>,
    wait_seconds: u32,
    expiry_profile_sha256: String,
    installation: receiver_installation_verifier::reference::Installation,
    capability_template: String,
    capability_policy_sha256: String,
}

impl FreshProfile {
    fn template(&self) -> Result<crate::protected_capability_policy::Template, ReceiverHold> {
        crate::protected_capability_policy::Template::from_policy(
            &self.capability_template,
            &self.capability_policy_sha256,
        )
        .map_err(|_| ReceiverHold::Configuration)
    }
    fn check(&self) -> Result<(), ReceiverHold> {
        use cgka_traits::reporting::event_id_is_valid;
        if self.schema != "heterodyne-protected-receiver-fresh.v3"
            || self.installation.check().is_err()
            || self.template().is_err()
            || self.receiver_uid != unsafe { libc::geteuid() }
            || self.consumer_uid == 0
            || self.consumer_uid == self.receiver_uid
            || self.wait_seconds == 0
            || self.wait_seconds > 86400
            || self.endpoints.is_empty()
            || !crate::protected_recovery::valid_group(&self.group)
            || !event_id_is_valid(&self.expected_welcomer)
            || self.expected_welcomer == self.account
            || !event_id_is_valid(&self.account)
            || !event_id_is_valid(&self.expiry_profile_sha256)
            || !event_id_is_valid(&self.storage_generation)
            || !event_id_is_valid(&self.key_package_ref)
            || self.operators.is_empty()
            || self.operators.len() > 64
            || self
                .operators
                .iter()
                .any(|key| !event_id_is_valid(key) || key == &self.account)
            || self
                .operators
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.operators.len()
        {
            return Err(ReceiverHold::Configuration);
        }
        Ok(())
    }
}

/// Retained original startup bytes and separately pinned concrete expiry policy.
struct FreshBinding {
    source: File,
    source_sha256: String,
    expiry: expiry::Profile,
    installation: Option<receiver_installation_verifier::reference::Verified>,
}
impl FreshBinding {
    fn new(
        source: File,
        expiry: File,
        profile: &FreshProfile,
        source_sha256: String,
    ) -> Result<Self, ReceiverHold> {
        let bound = Self {
            installation: Some(
                profile
                    .installation
                    .verify()
                    .map_err(|_| ReceiverHold::Configuration)?,
            ),
            source,
            source_sha256,
            expiry: expiry::Profile::open(expiry, &profile.expiry_profile_sha256)?,
        };
        bound.check()?;
        Ok(bound)
    }
    fn check(&self) -> Result<(), ReceiverHold> {
        if self
            .source
            .metadata()
            .map_err(|_| ReceiverHold::Configuration)?
            .uid()
            != 0
            || digest(&read(&self.source, 65536)?) != self.source_sha256
        {
            return Err(ReceiverHold::ChangedState);
        }
        if let Some(installation) = &self.installation {
            installation
                .check()
                .map_err(|_| ReceiverHold::ChangedState)?;
        }
        self.expiry.check()
    }
}

pub(super) fn entry() -> bool {
    if std::env::args_os().count() != 1 {
        return false;
    }
    (|| {
        let profile_file = inherited(3)?;
        if profile_file
            .metadata()
            .map_err(|_| ReceiverHold::Configuration)?
            .uid()
            != 0
        {
            return Err(ReceiverHold::Configuration);
        }
        let raw = read(&profile_file, 65536)?;
        let profile: FreshProfile =
            serde_json::from_slice(&raw).map_err(|_| ReceiverHold::Malformed)?;
        profile.check()?;
        anchor_custody::harden_process(profile.receiver_uid)?;
        let mut claimed = (4..=16).map(inherited).collect::<Result<Vec<_>, _>>()?;
        let expiry = claimed.pop().ok_or(ReceiverHold::Configuration)?;
        let files: [File; 12] = claimed
            .try_into()
            .map_err(|_| ReceiverHold::Configuration)?;
        let binding = FreshBinding::new(profile_file, expiry, &profile, digest(&raw))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| ReceiverHold::Engine)?;
        rt.block_on(run(profile, digest(&raw), files, binding))
    })()
    .is_ok()
}

/// Native evidence, rather than caller hashes, determines the enrolled baseline.
#[cfg(test)]
async fn finish<S: StorageProvider + 'static>(
    mut engine: crate::Engine<S>,
    profile: &FreshProfile,
    profile_sha: &str,
    files: OwnedFiles,
    intent: JoinIntent,
    wire: cgka_traits::TransportMessage,
) -> Result<ProtectedReceiver<S>, ReceiverHold> {
    profile.check()?;
    let files = Journal::prepare_fresh(files).map_err(|_| ReceiverHold::Journal)?;
    let operators = profile
        .operators
        .iter()
        .map(|value| {
            hex::decode(value)
                .map(MemberId::new)
                .map_err(|_| ReceiverHold::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if hex::encode(engine.self_id().as_slice()) != profile.account
        || operators.is_empty()
        || operators.len() > 64
        || operators.contains(&engine.self_id())
        || !engine
            .storage
            .list_groups()
            .map_err(|_| ReceiverHold::Engine)?
            .is_empty()
        || !engine
            .storage
            .list_pending_application_events()
            .map_err(|_| ReceiverHold::Engine)?
            .is_empty()
        || files
            .journal
            .metadata()
            .map_err(|_| ReceiverHold::Journal)?
            .len()
            != 0
        || files
            .anchor
            .metadata()
            .map_err(|_| ReceiverHold::Journal)?
            .len()
            != 0
    {
        return Err(ReceiverHold::ChangedState);
    }
    check_intent_alias(&files, &intent)?;
    let evidence = engine
        .receiver_join_enrolled(wire, intent, constraint(profile)?)
        .await
        .map_err(|_| ReceiverHold::Engine)?
        .ok_or(ReceiverHold::ChangedState)?;
    enroll_joined(engine, profile, profile_sha, files, evidence)
}

fn constraint(profile: &FreshProfile) -> Result<JoinConstraint, ReceiverHold> {
    Ok(JoinConstraint {
        expected_welcomer: MemberId::new(
            hex::decode(&profile.expected_welcomer).map_err(|_| ReceiverHold::Malformed)?,
        ),
        template: profile.template()?,
        group: GroupId::new(hex::decode(&profile.group).map_err(|_| ReceiverHold::Malformed)?),
        operators: profile
            .operators
            .iter()
            .map(|key| {
                hex::decode(key)
                    .map(MemberId::new)
                    .map_err(|_| ReceiverHold::Malformed)
            })
            .collect::<Result<Vec<_>, _>>()?,
        key_package_ref: hex::decode(&profile.key_package_ref)
            .map_err(|_| ReceiverHold::Malformed)?,
    })
}

fn enroll_joined<S: StorageProvider + 'static>(
    engine: crate::Engine<S>,
    profile: &FreshProfile,
    profile_sha: &str,
    files: OwnedFiles,
    evidence: JoinEvidence,
) -> Result<ProtectedReceiver<S>, ReceiverHold> {
    let expected = constraint(profile)?;
    let group = expected.group;
    let operators = expected.operators;
    if evidence.group != group {
        return Err(ReceiverHold::ChangedState);
    }
    let mut canonical_operators = profile.operators.clone();
    canonical_operators.sort();
    let enrollment = Enrollment {
        schema: Enrollment::SCHEMA.into(),
        installation_index_sha256: profile.installation.index_sha256.clone(),
        installation_source_sha256: profile
            .installation
            .source_sha256()
            .map_err(|_| ReceiverHold::Configuration)?,
        capability_template: profile.capability_template.clone(),
        capability_policy_sha256: profile.capability_policy_sha256.clone(),
        expiry_profile_sha256: profile.expiry_profile_sha256.clone(),
        account: profile.account.clone(),
        group: profile.group.clone(),
        operators: canonical_operators,
        expected_welcomer: profile.expected_welcomer.clone(),
        source_profile_sha256: profile_sha.to_owned(),
        storage_generation: profile.storage_generation.clone(),
        initial_native_state_sha256: digest(
            &serde_json::to_vec(&evidence.joined).map_err(|_| ReceiverHold::Malformed)?,
        ),
        welcome_provenance_sha256: evidence.digest().map_err(|_| ReceiverHold::ChangedState)?,
    };
    let journal = Journal::enroll(files, enrollment).map_err(|_| ReceiverHold::Journal)?;
    ProtectedReceiver::from_native_join(engine, group, operators, journal, evidence)
}

async fn run(
    profile: FreshProfile,
    profile_sha: String,
    files: [File; 12],
    binding: FreshBinding,
) -> Result<(), ReceiverHold> {
    let [
        key_file,
        dbkey_file,
        journal,
        journal_directory,
        storage_lease,
        anchor,
        anchor_directory,
        intent,
        intent_directory,
        account_dir,
        peer,
        cache_directory,
    ] = files;
    anchor_custody::check_descriptors(
        &anchor,
        &anchor_directory,
        &journal_directory,
        &account_dir,
    )?;
    // Keep the original storage lease through account opening, join and shutdown.
    storage_lease
        .try_lock()
        .map_err(|_| ReceiverHold::Journal)?;
    let dir = account_dir
        .metadata()
        .map_err(|_| ReceiverHold::Configuration)?;
    if !dir.is_dir() || dir.uid() != profile.receiver_uid || dir.mode() & 0o777 != 0o700 {
        return Err(ReceiverHold::Configuration);
    }
    let mut peer = checked_peer(peer, profile.consumer_uid)?;
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ReceiverHold::Configuration)?;
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ReceiverHold::Configuration)?;
    let mut nonce = [0; 32];
    let key = zeroize::Zeroizing::new(read(&key_file, 64)?);
    let dbkey = zeroize::Zeroizing::new(read(&dbkey_file, 64)?);
    if key.len() != 32 || dbkey.len() != 32 {
        return Err(ReceiverHold::Configuration);
    }
    let secret = nostr::SecretKey::from_slice(&key).map_err(|_| ReceiverHold::Configuration)?;
    let keys = nostr::Keys::new(secret);
    if keys.public_key().to_hex() != profile.account {
        return Err(ReceiverHold::ChangedState);
    }
    let sqlkey =
        SqlCipherKey::new(hex::encode(&*dbkey)).map_err(|_| ReceiverHold::Configuration)?;
    drop((key, dbkey));
    let fd = unsafe {
        libc::openat(
            account_dir.as_raw_fd(),
            c"account.sqlite3".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(ReceiverHold::Configuration);
    }
    let db_file = unsafe { File::from_raw_fd(fd) };
    let before = db_file
        .metadata()
        .map_err(|_| ReceiverHold::Configuration)?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != profile.receiver_uid
        || before.mode() & 0o777 != 0o600
    {
        return Err(ReceiverHold::Configuration);
    }
    let path = PathBuf::from(format!(
        "/proc/self/fd/{}/account.sqlite3",
        account_dir.as_raw_fd()
    ));
    let storage =
        SqliteAccountStorage::open_encrypted(&path, &sqlkey).map_err(|_| ReceiverHold::Engine)?;
    let after = std::fs::metadata(&path).map_err(|_| ReceiverHold::ChangedState)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(ReceiverHold::ChangedState);
    }
    // Keep the actual SQLCipher connection alive even if enrollment consumes and
    // drops the Engine on an error after the native Welcome committed.
    let retained_storage = storage.clone();
    let mut engine = owned_routed_engine(storage, keys, profile.template()?)?;
    check_cache_devices(
        &cache_directory,
        &[
            &journal,
            &journal_directory,
            &anchor,
            &anchor_directory,
            &intent,
            &intent_directory,
            &account_dir,
            &db_file,
        ],
    )?;
    for file in [&journal, &anchor, &intent] {
        check_writable(file)?;
    }
    check_fresh_account(&engine, &profile)?;
    peer.read_exact(&mut nonce)
        .map_err(|_| ReceiverHold::Configuration)?;
    let spool = relay_spool::anonymous(&cache_directory)?;
    let files = Journal::prepare_fresh(OwnedFiles {
        journal,
        journal_directory,
        storage_lease,
        anchor,
        anchor_directory,
    })
    .map_err(|_| ReceiverHold::Journal)?;
    let intent = JoinIntent {
        file: intent,
        directory: intent_directory,
    };
    check_intent_alias(&files, &intent)?;
    let retained_locks = retain_lock_descriptions(&files)?;
    let sdk = nostr_sdk::Client::builder().build();
    let adapter = NostrTransportAdapter::new(Arc::new(NostrSdkRelayClient::new(sdk.clone())));
    let forwarder = forward(sdk.clone(), adapter.clone(), spool);
    // Retain a committed receiver across every post-enrollment error until relay shutdown.
    let mut retained = None;
    let result = async {
        tokio::time::timeout(Duration::from_secs(30), adapter.activate_account(TransportAccountActivation {
            account_id: engine.self_id(), inbox_endpoints: profile.endpoints.clone(), group_subscriptions:vec![], since:None,
        })).await.map_err(|_| ReceiverHold::Engine)?.map_err(|_| ReceiverHold::Engine)?;
        let deadline = tokio::time::Instant::now()+Duration::from_secs(u64::from(profile.wait_seconds));
        let evidence = loop {
            if forwarder.is_finished() || tokio::time::Instant::now() >= deadline { return Err(ReceiverHold::Engine); }
            let wait = deadline.min(tokio::time::Instant::now()+Duration::from_secs(1));
            if let Ok(delivery) = tokio::time::timeout_at(wait, adapter.receive()).await {
                let Some(delivery) = delivery.map_err(|_| ReceiverHold::Engine)? else { return Err(ReceiverHold::Engine); };
                if delivery.account_id != engine.self_id() { return Err(ReceiverHold::ChangedState); }
                if let Some(evidence) = attempt_welcome(&mut engine, &profile, &intent, &binding, delivery.message).await? {
                    break evidence;
                }
            }
        };
        retain_enrollment(&mut retained, engine, &profile, &profile_sha, files, evidence, &binding)?;
        let receiver = retained.as_ref().ok_or(ReceiverHold::Journal)?;
        // Enrollment is already durable; relay lifetime no longer determines it.
        let ReceiverJournal::Ordered(journal) = &receiver.journal else { return Err(ReceiverHold::Journal); };
        let enrolled = journal.enrollment().map_err(|_| ReceiverHold::Journal)?;
        let header = journal.source_at(1).map_err(|_| ReceiverHold::Journal)?;
        let output = serde_json::to_vec(&serde_json::json!({
            "schema":"heterodyne-owned-fresh-enrollment.v3", "nonce_hex":hex::encode(nonce),
            "startup_profile_sha256":profile_sha,"enrollment_sha256":enrolled.canonical_sha256().map_err(|_| ReceiverHold::Malformed)?,"enrollment":enrolled,
            "header_record":header.body,"header_sha256":journal.header_digest().map_err(|_| ReceiverHold::Journal)?,"checkpoint":journal.checkpoint(),
        })).map_err(|_| ReceiverHold::Malformed)?;
        write_frame(&mut peer,&output)?;
        // Receiver owns actual account/journal until after finite SDK shutdown.
        Ok(())
    }.await;
    if result.is_err() {
        // Conservative on purpose: no failure response authorizes a retry or
        // asserts that native state stayed unchanged, even before intent.
        let output = serde_json::to_vec(&serde_json::json!({
            "schema":"heterodyne-owned-fresh-enrollment-hold.v1", "nonce_hex":hex::encode(nonce),
            "startup_profile_sha256":profile_sha, "requires_reconciliation":true,
            "automatic_replay_forbidden":true,"native_effects_may_be_unknown":true,
        }));
        if let Ok(output) = output {
            let _ = write_frame(&mut peer, &output);
        }
    }
    forwarder.abort();
    let _ = forwarder.await;
    let shutdown = tokio::time::timeout(Duration::from_secs(5), sdk.shutdown()).await;
    drop((
        retained,
        retained_locks,
        retained_storage,
        key_file,
        dbkey_file,
        account_dir,
        db_file,
    ));
    if shutdown.is_err() {
        return Err(ReceiverHold::Engine);
    }
    result
}

// Duplicates share the original locked open-file descriptions. Keep them outside
// the consuming enrollment future: every error path must retain ownership until
// the forwarder is reaped and finite SDK shutdown has finished.
fn retain_lock_descriptions(files: &OwnedFiles) -> Result<[File; 3], ReceiverHold> {
    Ok([
        files
            .storage_lease
            .try_clone()
            .map_err(|_| ReceiverHold::Journal)?,
        files
            .journal
            .try_clone()
            .map_err(|_| ReceiverHold::Journal)?,
        files
            .anchor
            .try_clone()
            .map_err(|_| ReceiverHold::Journal)?,
    ])
}

// One production postcommit operation: durable enrollment and retention must precede
// the policy check. The caller keeps `retained` alive until SDK/forwarder shutdown.
fn retain_enrollment<S: StorageProvider + 'static>(
    retained: &mut Option<ProtectedReceiver<S>>,
    engine: crate::Engine<S>,
    profile: &FreshProfile,
    profile_sha: &str,
    files: OwnedFiles,
    evidence: JoinEvidence,
    binding: &FreshBinding,
) -> Result<(), ReceiverHold> {
    *retained = Some(enroll_joined(
        engine,
        profile,
        profile_sha,
        files,
        evidence,
    )?);
    binding.check()
}

async fn attempt_welcome<S: StorageProvider + 'static>(
    engine: &mut crate::Engine<S>,
    profile: &FreshProfile,
    intent: &JoinIntent,
    binding: &FreshBinding,
    wire: cgka_traits::TransportMessage,
) -> Result<Option<JoinEvidence>, ReceiverHold> {
    if !matches!(&wire.envelope, TransportEnvelope::Welcome {recipient} if recipient == &engine.self_id())
    {
        return Ok(None);
    }
    binding.check()?;
    let attempt = JoinIntent {
        file: intent.file.try_clone().map_err(|_| ReceiverHold::Journal)?,
        directory: intent
            .directory
            .try_clone()
            .map_err(|_| ReceiverHold::Journal)?,
    };
    engine
        .receiver_join_enrolled(wire, attempt, constraint(profile)?)
        .await
        .map_err(|_| ReceiverHold::Engine)
}

fn check_writable(file: &File) -> Result<(), ReceiverHold> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDWR || flags & libc::O_APPEND != 0 {
        return Err(ReceiverHold::Configuration);
    }
    Ok(())
}

fn check_cache_devices(cache: &File, durable: &[&File]) -> Result<(), ReceiverHold> {
    let device = cache
        .metadata()
        .map_err(|_| ReceiverHold::Configuration)?
        .dev();
    for file in durable {
        if file
            .metadata()
            .map_err(|_| ReceiverHold::Configuration)?
            .dev()
            == device
        {
            return Err(ReceiverHold::Configuration);
        }
    }
    Ok(())
}

fn check_fresh_account<S: StorageProvider + 'static>(
    engine: &crate::Engine<S>,
    profile: &FreshProfile,
) -> Result<(), ReceiverHold> {
    if !engine
        .storage
        .list_groups()
        .map_err(|_| ReceiverHold::Engine)?
        .is_empty()
        || !engine
            .storage
            .list_pending_application_events()
            .map_err(|_| ReceiverHold::Engine)?
            .is_empty()
        || !engine
            .durably_owned_key_packages()
            .map_err(|_| ReceiverHold::Engine)?
            .iter()
            .any(|kp| {
                crate::key_package::key_package_metadata(kp).is_ok_and(|metadata| {
                    metadata.key_package_ref_hex == profile.key_package_ref
                        && profile
                            .template()
                            .is_ok_and(|t| t.validate_metadata(&metadata).is_ok())
                })
            })
    {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(())
}

fn check_intent_alias(files: &OwnedFiles, intent: &JoinIntent) -> Result<(), ReceiverHold> {
    let key = |file: &File| {
        file.metadata()
            .map(|m| (m.dev(), m.ino()))
            .map_err(|_| ReceiverHold::Configuration)
    };
    let own = key(&intent.file)?;
    if [&files.journal, &files.anchor, &files.storage_lease]
        .into_iter()
        .any(|file| key(file).map_or(true, |id| id == own))
    {
        return Err(ReceiverHold::Configuration);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protected_join::tests::{intent, invitation, recovery_files};
    use cgka_traits::{GroupStorage, MessageStorage};

    fn binding(root: &std::path::Path, p: &mut FreshProfile) -> FreshBinding {
        use std::os::unix::fs::PermissionsExt;
        let bytes =
            br#"{"schema":"heterodyne-receiver-expiry.v1","max_approval_lifetime_ms":60000}"#;
        p.expiry_profile_sha256 = digest(bytes);
        let source = root.join("fresh-profile");
        let policy = root.join("expiry-profile");
        std::fs::write(&source, serde_json::to_vec(p).unwrap()).unwrap();
        std::fs::write(&policy, bytes).unwrap();
        for path in [&source, &policy] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let sha = digest(&std::fs::read(&source).unwrap());
        // Mechanical native join/expiry fixture. Production constructor always
        // verifies a complete installed tree; these tests do not qualify custody.
        FreshBinding {
            source: File::open(source).unwrap(),
            source_sha256: sha,
            expiry: expiry::Profile::open(File::open(policy).unwrap(), &p.expiry_profile_sha256)
                .unwrap(),
            installation: None,
        }
    }

    #[tokio::test]
    async fn actual_loop_attempt_rejects_oversized_input_then_accepts_native_welcome() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        let (mut engine, storage, wire, group, operator) = invitation().await;
        let mut p = profile(&engine, &group, &operator, &wire);
        let root = tempfile::tempdir().unwrap();
        let binding = binding(root.path(), &mut p);
        let intent = intent(root.path());
        let mut oversized = wire.clone();
        oversized.payload = vec![255; 400_000];
        assert!(
            attempt_welcome(&mut engine, &p, &intent, &binding, oversized)
                .await
                .unwrap()
                .is_none()
        );
        assert!(storage.list_groups().unwrap().is_empty());
        assert_eq!(intent.file.metadata().unwrap().len(), 0);
        assert!(
            attempt_welcome(&mut engine, &p, &intent, &binding, wire)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(storage.list_groups().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn changed_retained_policy_or_source_refuses_before_native_intent() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        for name in ["fresh-profile", "expiry-profile"] {
            let (mut engine, storage, wire, group, operator) = invitation().await;
            let root = tempfile::tempdir().unwrap();
            let mut p = profile(&engine, &group, &operator, &wire);
            let binding = binding(root.path(), &mut p);
            let intent = intent(root.path());
            // Mutation after initial startup validation, during the Welcome wait.
            std::fs::write(root.path().join(name), b"changed retained bytes").unwrap();
            assert!(matches!(
                attempt_welcome(&mut engine, &p, &intent, &binding, wire).await,
                Err(ReceiverHold::ChangedState)
            ));
            assert!(storage.list_groups().unwrap().is_empty());
            assert_eq!(intent.file.metadata().unwrap().len(), 0);
            assert!(
                storage
                    .list_pending_application_events()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn policy_change_after_native_commit_preserves_durable_v2_header_and_holds() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        let (mut engine, storage, wire, group, operator) = invitation().await;
        let root = tempfile::tempdir().unwrap();
        let mut p = profile(&engine, &group, &operator, &wire);
        let binding = binding(root.path(), &mut p);
        let files = Journal::prepare_fresh(recovery_files(root.path())).unwrap();
        let intent = intent(root.path());
        let evidence = attempt_welcome(&mut engine, &p, &intent, &binding, wire)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(storage.list_groups().unwrap(), vec![group]);
        // This models mutation in the irreversible native-commit→header window.
        // No policy guard may prevent retaining the successful native join.
        std::fs::write(root.path().join("expiry-profile"), b"changed after join").unwrap();
        let mut retained = None;
        assert!(matches!(
            retain_enrollment(
                &mut retained,
                engine,
                &p,
                &binding.source_sha256,
                files,
                evidence,
                &binding
            ),
            Err(ReceiverHold::ChangedState)
        ));
        let receiver = retained.as_ref().unwrap();
        let ReceiverJournal::Ordered(journal) = &receiver.journal else {
            panic!("ordered")
        };
        let enrolled = journal.enrollment().unwrap();
        assert_eq!(enrolled.source_profile_sha256, binding.source_sha256);
        assert_eq!(enrolled.expiry_profile_sha256, p.expiry_profile_sha256);
        assert_eq!(journal.source_at(1).unwrap().body["kind"], "header-v3");
        let bytes = std::fs::read(root.path().join("receiver/journal")).unwrap();
        // A separate owner cannot acquire the account lease during postcommit HOLD.
        let other = recovery_files(root.path());
        assert!(other.storage_lease.try_lock().is_err());
        drop(other);
        drop(retained);
        let reopened = Journal::reopen(recovery_files(root.path()), &enrolled).unwrap();
        assert_eq!(reopened.enrollment().unwrap(), enrolled);
        assert_eq!(
            std::fs::read(root.path().join("receiver/journal")).unwrap(),
            bytes
        );
        assert!(
            storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn failed_postcommit_journal_enrollment_keeps_original_locks_until_cleanup() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }
        let (mut engine, storage, wire, group, operator) = invitation().await;
        let root = tempfile::tempdir().unwrap();
        let mut p = profile(&engine, &group, &operator, &wire);
        let binding = binding(root.path(), &mut p);
        let files = Journal::prepare_fresh(recovery_files(root.path())).unwrap();
        let locks = retain_lock_descriptions(&files).unwrap();
        let evidence = attempt_welcome(&mut engine, &p, &intent(root.path()), &binding, wire)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(storage.list_groups().unwrap(), vec![group]);
        // Real Journal::enroll now fails after actual native commit and consumes
        // its Engine/files. This is not the successful-return policy-check path.
        std::fs::write(
            root.path().join("receiver/journal"),
            b"incomplete external journal",
        )
        .unwrap();
        let mut retained = None;
        assert!(matches!(
            retain_enrollment(
                &mut retained,
                engine,
                &p,
                &binding.source_sha256,
                files,
                evidence,
                &binding
            ),
            Err(ReceiverHold::Journal)
        ));
        assert!(retained.is_none());
        let other = recovery_files(root.path());
        for file in [&other.storage_lease, &other.journal, &other.anchor] {
            assert!(file.try_lock().is_err());
        }
        // Production holds these original descriptions through forwarder reaping
        // and SDK shutdown, even though the enrollment future has returned Err.
        drop(locks);
        for file in [&other.storage_lease, &other.journal, &other.anchor] {
            file.try_lock().unwrap();
        }
        assert_eq!(
            std::fs::read(root.path().join("receiver/journal")).unwrap(),
            b"incomplete external journal"
        );
        assert!(
            !storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn actual_fresh_v2_join_reopens_expiry_then_real_mls_decision_consumes_once() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        use super::super::super::tests::{Relay, client, finite_original, reaction};
        use cgka_traits::{
            GroupStorage,
            app_components::{
                AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
                encode_nostr_routing_v1,
            },
            engine::CreateGroupRequest,
        };
        let mut operator = client(b"fresh-v2-operator");
        let mut engine = client(b"fresh-v2-receiver");
        let mut kp = engine.fresh_key_package().await.unwrap();
        kp.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::types::MessageId::new(vec![4; 32]),
        });
        let route = NostrRoutingV1::new([7; 32], vec!["wss://semantic.invalid".into()]).unwrap();
        let (group, created) = operator
            .create_group(CreateGroupRequest {
                name: "fresh-v2".into(),
                description: String::new(),
                members: vec![kp],
                required_features: vec![],
                app_components: vec![AppComponentData {
                    component_id: NOSTR_ROUTING_COMPONENT_ID,
                    data: encode_nostr_routing_v1(&route).unwrap(),
                }],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupCreated {
            pending,
            mut welcomes,
        } = created
        else {
            panic!("created")
        };
        operator.confirm_published(pending).await.unwrap();
        engine.drain_events();
        operator.drain_events();
        let wire = welcomes.remove(0);
        let root = tempfile::tempdir().unwrap();
        let mut p = FreshProfile {
            schema: "heterodyne-protected-receiver-fresh.v3".into(),
            receiver_uid: unsafe { libc::geteuid() },
            consumer_uid: unsafe { libc::geteuid() } + 1,
            account: hex::encode(engine.self_id().as_slice()),
            group: hex::encode(group.as_slice()),
            operators: vec![hex::encode(operator.self_id().as_slice())],
            expected_welcomer: hex::encode(operator.self_id().as_slice()),
            storage_generation: "55".repeat(32),
            key_package_ref: crate::key_package::key_package_metadata(
                &engine.durably_owned_key_packages().unwrap()[0],
            )
            .unwrap()
            .key_package_ref_hex,
            endpoints: vec![TransportEndpoint::from("wss://semantic.invalid")],
            wait_seconds: 1,
            expiry_profile_sha256: "77".repeat(32),
            installation: receiver_installation_verifier::reference::Installation {
                root: std::path::PathBuf::from(format!(
                    "/opt/heterodyne-receiver/releases/{}",
                    "aa".repeat(32)
                )),
                index_sha256: "aa".repeat(32),
                recipe_id: "fixture-only".into(),
                platform_id: "fixture-only".into(),
            },
            capability_template: "routing-only-v1".into(),
            capability_policy_sha256: crate::protected_capability_policy::routing_only_v1()
                .policy_sha256(),
        };
        let binding = binding(root.path(), &mut p);
        let files = Journal::prepare_fresh(recovery_files(root.path())).unwrap();
        let intent = intent(root.path());
        let evidence = attempt_welcome(&mut engine, &p, &intent, &binding, wire)
            .await
            .unwrap()
            .unwrap();
        let receiver = enroll_joined(engine, &p, &binding.source_sha256, files, evidence).unwrap();
        binding.check().unwrap();
        let ReceiverJournal::Ordered(journal) = &receiver.journal else {
            panic!("ordered")
        };
        let enrolled = journal.enrollment().unwrap();
        let ProtectedReceiver {
            engine, journal, ..
        } = receiver;
        drop(journal);
        let journal = Journal::reopen(recovery_files(root.path()), &enrolled).unwrap();
        let receiver = ProtectedReceiver::reopen_ordered(
            engine,
            group.clone(),
            vec![operator.self_id()],
            journal,
        )
        .unwrap();
        assert_eq!(
            receiver.engine.storage.list_groups().unwrap(),
            vec![group.clone()]
        );
        let relay = Arc::new(Relay::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        adapter
            .activate_account(TransportAccountActivation {
                account_id: receiver.engine.self_id(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![],
                since: None,
            })
            .await
            .unwrap();
        let mut factory = SemanticFactory::new(receiver, adapter, p.endpoints.clone())
            .unwrap()
            .with_expiry_profile(File::open(root.path().join("expiry-profile")).unwrap())
            .unwrap();
        let original = finite_original("ask3", &group);
        let original_sha = digest(&original.operation);
        factory.post(original).await.unwrap();
        let published = relay.wires.lock().unwrap().clone();
        for wire in published {
            operator.ingest(wire).await.unwrap();
        }
        operator.drain_events();
        let target = factory.asks["ask3"].app_ids[0].clone();
        let yes = reaction(&mut operator, &factory, &target, "👍").await;
        assert_eq!(factory.ingest(yes).await.unwrap(), Some("ask3".into()));
        assert_eq!(
            factory
                .consume("ask3", &original_sha)
                .unwrap()
                .operation_sha256,
            original_sha
        );
        assert!(factory.consume("ask3", &original_sha).is_err());
    }

    #[test]
    fn durable_descriptors_require_nonappend_readwrite_and_cache_isolation() {
        use std::fs::OpenOptions;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("durable");
        let rw = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(check_writable(&rw).is_ok());
        assert!(matches!(
            check_writable(&File::open(&path).unwrap()),
            Err(ReceiverHold::Configuration)
        ));
        let append = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            check_writable(&append),
            Err(ReceiverHold::Configuration)
        ));
        let cache = File::open(root.path()).unwrap();
        assert!(matches!(
            check_cache_devices(&cache, &[&rw]),
            Err(ReceiverHold::Configuration)
        ));
        // Every durable position is checked, not only the first directory.
        if let Ok(other) = File::open("/dev/shm")
            && other.metadata().unwrap().dev() != cache.metadata().unwrap().dev()
        {
            assert!(check_cache_devices(&other, &[&rw, &cache]).is_ok());
            assert!(matches!(
                check_cache_devices(&cache, &[&other, &rw]),
                Err(ReceiverHold::Configuration)
            ));
        }
    }

    #[tokio::test]
    async fn fresh_account_preflight_checks_actual_owned_key_package_and_native_state() {
        let (mut engine, _, wire, group, operator) = invitation().await;
        let mut p = profile(&engine, &group, &operator, &wire);
        // Legacy generic Engine defaults cannot stand in for the enrolled factory.
        assert!(check_fresh_account(&engine, &p).is_err());
        let mut selected = owned_routed_engine(
            SqliteAccountStorage::in_memory().unwrap(),
            nostr::Keys::generate(),
            crate::protected_capability_policy::routing_only_v1(),
        )
        .unwrap();
        let kp = selected.fresh_key_package().await.unwrap();
        let mut matching = profile(&selected, &group, &operator, &wire);
        matching.key_package_ref = crate::key_package_metadata(&kp)
            .unwrap()
            .key_package_ref_hex;
        assert!(check_fresh_account(&selected, &matching).is_ok());
        p.key_package_ref = "aa".repeat(32);
        assert!(matches!(
            check_fresh_account(&engine, &p),
            Err(ReceiverHold::ChangedState)
        ));
        p.key_package_ref = crate::protected_join::tests::key_package_ref(&wire);
        let root = tempfile::tempdir().unwrap();
        engine
            .receiver_join_owned(wire, intent(root.path()))
            .await
            .unwrap();
        assert!(matches!(
            check_fresh_account(&engine, &p),
            Err(ReceiverHold::ChangedState)
        ));
    }

    fn profile(
        engine: &crate::Engine<SqliteAccountStorage>,
        group: &GroupId,
        operator: &MemberId,
        wire: &cgka_traits::TransportMessage,
    ) -> FreshProfile {
        FreshProfile {
            schema: "heterodyne-protected-receiver-fresh.v3".into(),
            receiver_uid: unsafe { libc::geteuid() },
            consumer_uid: unsafe { libc::geteuid() }.checked_add(1).unwrap(),
            account: hex::encode(engine.self_id().as_slice()),
            group: hex::encode(group.as_slice()),
            operators: vec![hex::encode(operator.as_slice())],
            expected_welcomer: hex::encode(operator.as_slice()),
            storage_generation: "55".repeat(32),
            key_package_ref: crate::protected_join::tests::key_package_ref(wire),
            endpoints: vec![TransportEndpoint("wss://fixture.invalid".into())],
            wait_seconds: 1,
            expiry_profile_sha256: "77".repeat(32),
            installation: receiver_installation_verifier::reference::Installation {
                root: std::path::PathBuf::from(format!(
                    "/opt/heterodyne-receiver/releases/{}",
                    "aa".repeat(32)
                )),
                index_sha256: "aa".repeat(32),
                recipe_id: "fixture-only".into(),
                platform_id: "fixture-only".into(),
            },
            capability_template: "routing-only-v1".into(),
            capability_policy_sha256: crate::protected_capability_policy::routing_only_v1()
                .policy_sha256(),
        }
    }

    #[tokio::test]
    async fn fresh_entry_derives_native_enrollment_retains_original_then_reopens() {
        if !crate::protected_recovery::root_expiry_fixture_available() {
            return;
        }

        let (engine, storage, wire, group, operator) = invitation().await;
        let root = tempfile::tempdir().unwrap();
        let mut profile = profile(&engine, &group, &operator, &wire);
        let binding = binding(root.path(), &mut profile);
        let profile_sha = binding.source_sha256.clone();
        binding.check().unwrap();
        let receiver = finish(
            engine,
            &profile,
            &profile_sha,
            recovery_files(root.path()),
            intent(root.path()),
            wire.clone(),
        )
        .await
        .unwrap();
        assert!(
            storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
        let ReceiverJournal::Ordered(journal) = &receiver.journal else {
            panic!("ordered")
        };
        let enrolled = journal.enrollment().unwrap();
        let actual = receiver
            .engine
            .with_mls_group(&group, |native| {
                crate::protected_merge::Projection::read(native)
            })
            .unwrap();
        assert_eq!(
            enrolled.initial_native_state_sha256,
            digest(&serde_json::to_vec(&actual).unwrap())
        );
        assert_eq!(enrolled.source_profile_sha256, profile_sha);
        assert_eq!(
            enrolled.expiry_profile_sha256,
            profile.expiry_profile_sha256
        );
        assert_ne!(
            enrolled.source_profile_sha256,
            enrolled.expiry_profile_sha256
        );
        assert_eq!(journal.source_at(1).unwrap().body["kind"], "header-v3");
        let source = journal.source_at(2).unwrap();
        assert_eq!(
            source.body["value"]["native_join"]["original_wire"],
            serde_json::to_value(&wire).unwrap()
        );
        let (sequence, _) = journal.checkpoint();
        assert_eq!(sequence, 2);
        let ProtectedReceiver {
            engine, journal, ..
        } = receiver;
        drop(journal);
        let journal = Journal::reopen(recovery_files(root.path()), &enrolled).unwrap();
        let reopened =
            ProtectedReceiver::reopen_ordered(engine, group, vec![operator], journal).unwrap();
        assert!(
            reopened
                .engine
                .storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn existing_anchor_or_invalid_policy_refuses_before_native_welcome() {
        for invalid_policy in [false, true] {
            let (engine, storage, wire, group, operator) = invitation().await;
            let root = tempfile::tempdir().unwrap();
            let mut p = profile(&engine, &group, &operator, &wire);
            let mut files = recovery_files(root.path());
            if invalid_policy {
                p.operators.push(p.operators[0].clone());
            } else {
                files.anchor.write_all(b"retained unknown").unwrap();
                files.anchor.sync_all().unwrap();
            }
            let actual_intent = intent(root.path());
            assert!(
                finish(engine, &p, &"66".repeat(32), files, actual_intent, wire)
                    .await
                    .is_err()
            );
            assert!(storage.list_groups().unwrap().is_empty());
            assert!(
                std::fs::read(root.path().join("join-intent"))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn aliased_intent_refuses_before_native_join() {
        for alias in ["journal", "anchor", "lease"] {
            let (engine, storage, wire, group, operator) = invitation().await;
            let root = tempfile::tempdir().unwrap();
            let p = profile(&engine, &group, &operator, &wire);
            let files = recovery_files(root.path());
            let file = match alias {
                "journal" => &files.journal,
                "anchor" => &files.anchor,
                _ => &files.storage_lease,
            };
            let intent = JoinIntent {
                file: file.try_clone().unwrap(),
                directory: File::open(root.path()).unwrap(),
            };
            assert!(matches!(
                finish(engine, &p, &"66".repeat(32), files, intent, wire).await,
                Err(ReceiverHold::Configuration)
            ));
            assert!(storage.list_groups().unwrap().is_empty());
            assert!(
                storage
                    .list_pending_application_events()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn wrong_actual_group_rolls_back_without_burning_keypackage_or_intent() {
        let (engine, storage, wire, group, operator) = invitation().await;
        let root = tempfile::tempdir().unwrap();
        let mut p = profile(&engine, &group, &operator, &wire);
        p.group = "77".repeat(16);
        assert!(
            finish(
                engine,
                &p,
                &"66".repeat(32),
                recovery_files(root.path()),
                intent(root.path()),
                wire.clone()
            )
            .await
            .is_err()
        );
        assert!(
            std::fs::read(root.path().join("join-intent"))
                .unwrap()
                .is_empty()
        );
        assert!(
            storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
        assert!(storage.list_groups().unwrap().is_empty());
        assert!(
            std::fs::read(root.path().join("receiver/journal"))
                .unwrap()
                .is_empty()
        );
        assert!(
            std::fs::read(root.path().join("consumer/anchor"))
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test]
    async fn journal_write_failure_after_join_keeps_pending_welcome_and_original_intent() {
        let (engine, storage, wire, group, operator) = invitation().await;
        let root = tempfile::tempdir().unwrap();
        let p = profile(&engine, &group, &operator, &wire);
        let mut files = recovery_files(root.path());
        files.journal = std::fs::OpenOptions::new()
            .read(true)
            .open(root.path().join("receiver/journal"))
            .unwrap();
        assert!(matches!(
            finish(
                engine,
                &p,
                &"66".repeat(32),
                files,
                intent(root.path()),
                wire
            )
            .await,
            Err(ReceiverHold::Journal)
        ));
        assert_eq!(storage.list_pending_application_events().unwrap().len(), 1);
        assert!(
            !std::fs::read(root.path().join("join-intent"))
                .unwrap()
                .is_empty()
        );
        assert!(
            std::fs::read(root.path().join("receiver/journal"))
                .unwrap()
                .is_empty()
        );
    }
}
