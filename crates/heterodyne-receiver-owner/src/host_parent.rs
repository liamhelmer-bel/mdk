//! One root host parent owns original inputs and the lifetime OFD until both
//! namespace bootstrap and fixed host admission child have actually ceased.
use crate::{
    host_channel as channel, host_child::HostChild, host_inputs as pins, initializer_entry as input,
};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    time::Duration,
};
type Result<T> = std::result::Result<T, ()>;
/// No Deserialize, public constructor, file loader, or generic execute method.
struct OwnedConsumedDeployment {
    raw: Vec<u8>,
    process: File,
    process_sha: String,
    bootstrap_nonce: [u8; 32],
}
fn equal(v: &Value, key: &str, expected: &str) -> Result<()> {
    if v.get(key).and_then(Value::as_str) != Some(expected) {
        return Err(());
    }
    Ok(())
}
fn check_result(
    raw: &[u8],
    nonce: &[u8; 32],
    process: &[u8],
    p: &input::Profile,
    profile: &pins::ParentProfile,
    packet: &[u8],
) -> Result<()> {
    let v = crate::native_frame::read(raw)?;
    if v.as_object().ok_or(())?.len() != 12 {
        return Err(());
    }
    for (key, value) in [
        ("schema", "heterodyne-owned-consumed.v3"),
        ("nonce_hex", hex::encode(nonce).as_str()),
        ("startup_profile_sha256", pins::sha(process).as_str()),
        (
            "installation_index_sha256",
            profile.installation_index_sha256.as_str(),
        ),
        (
            "installation_source_sha256",
            profile.installation_source_sha256.as_str(),
        ),
        ("capability_template", p.capability_template.as_str()),
        (
            "capability_policy_sha256",
            p.capability_policy_sha256.as_str(),
        ),
    ] {
        equal(&v, key, value)?;
    }
    let process =
        receiver_installation_verifier::installation::parse_canonical(process).map_err(|_| ())?;
    equal(
        &process,
        "schema",
        "heterodyne-protected-receiver-process.v3",
    )?;
    if process["receiver_uid"] != 899
        || process["consumer_uid"] != 898
        || process["installation"] != serde_json::to_value(&p.installation).map_err(|_| ())?
        || process["endpoints"] != json!(p.inbox_endpoints)
        || process["wait_seconds"] != p.wait_seconds
    {
        return Err(());
    }
    let enrollment = process.get("enrollment").ok_or(())?;
    for (key, value) in [
        ("schema", "heterodyne-receiver-enrollment.v3"),
        ("group", p.group.as_str()),
        ("storage_generation", p.storage_generation.as_str()),
        ("expected_welcomer", p.expected_welcomer.as_str()),
        ("expiry_profile_sha256", p.expiry_profile_sha256.as_str()),
        (
            "installation_index_sha256",
            profile.installation_index_sha256.as_str(),
        ),
        (
            "installation_source_sha256",
            profile.installation_source_sha256.as_str(),
        ),
        ("capability_template", p.capability_template.as_str()),
        (
            "capability_policy_sha256",
            p.capability_policy_sha256.as_str(),
        ),
    ] {
        equal(enrollment, key, value)?;
    }
    if enrollment["operators"] != json!(p.operators) {
        return Err(());
    }
    equal(
        &v,
        "journal_profile_sha256",
        enrollment["source_profile_sha256"].as_str().ok_or(())?,
    )?;
    // Enrollment digest/header/card/semantic lineage remains native-attested.
    // Root independently checks exact retained original operation and known pins.
    equal(&v["original"], "operation", &hex::encode(packet))?;
    equal(&v["receipt"], "packet_sha256", &pins::sha(packet))?;
    Ok(())
}
impl OwnedConsumedDeployment {
    fn accept(
        child: HostChild,
        incoming: &File,
        nonce: [u8; 32],
        p: &input::Profile,
        profile: &pins::ParentProfile,
        packet: &[u8],
    ) -> Result<Self> {
        crate::supervision::ready(
            incoming,
            crate::supervision::bootstrap(p.deadline_unix_ms, p.wait_seconds)?,
        )?;
        let (raw, process) = channel::receive(incoming, child.pid(), channel::MAX_NATIVE, true)?;
        let process = process.ok_or(())?;
        let bytes = input::protected_bytes(&process)?;
        check_result(&raw, &nonce, &bytes, p, profile, packet)?;
        child.normal_exit(crate::supervision::CESSATION)?;
        Ok(Self {
            raw,
            process,
            process_sha: pins::sha(&bytes),
            bootstrap_nonce: nonce,
        })
    }
    fn admission(
        self,
        verified: &receiver_installation_verifier::reference::HostVerified,
        admission: &File,
        profile: &pins::ParentProfile,
        lease: &File,
        artifacts: &[(i32, &File)],
    ) -> Result<()> {
        verified.check().map_err(|_| ())?;
        // This root-child freshness domain is never disclosed to the receiver.
        let (nonce, nonce_file) = channel::nonce()?;
        if nonce == self.bootstrap_nonce {
            return Err(());
        }
        let python = verified.python();
        let closure = verified.closure().map_err(|_| ())?;
        let expected = closure
            .iter()
            .cloned()
            .into_iter()
            .find(|(p, _)| p == &python)
            .ok_or(())?
            .1;
        let executable = pins::binary(&python, &expected)?;
        let prefix = python.parent().and_then(|p| p.parent()).ok_or(())?;
        let paths = serde_json::to_string(&[
            prefix.join("lib/python3.12"),
            prefix.join("lib/python3.12/lib-dynload"),
            verified.product_source(),
            verified.purelib(),
        ])
        .map_err(|_| ())?;
        let prologue = format!(
            "import sys; sys.path={paths}; from heterodyne.actions.deployment_admission_entry import _entry; sys.exit(_entry())"
        );
        // No nonexistent future module or mutable checkout may be substituted.
        if !closure.iter().any(|(p, _)| {
            p == &verified
                .product_source()
                .join("heterodyne/actions/deployment_admission_entry.py")
        }) {
            return Err(());
        }
        let (incoming, outgoing) = crate::owner_entry::channel()?;
        crate::initializer_handoff::enable_credentials(&incoming).map_err(|_| ())?;
        crate::initializer_handoff::enable_credentials(&outgoing).map_err(|_| ())?;
        let mut inputs = vec![
            (3, admission),
            (4, &outgoing),
            (5, lease),
            (6, &nonce_file),
            (7, &self.process),
        ];
        inputs.extend_from_slice(artifacts);
        let child = HostChild::admission(
            &executable,
            python.to_str().ok_or(())?,
            &prologue,
            &inputs,
            lease.try_clone().map_err(|_| ())?,
        )?;
        drop(inputs);
        drop(outgoing);
        let metadata=receiver_installation_verifier::installation::canonical(&json!({"schema":"heterodyne-owned-deployment-admission.v1","nonce_hex":hex::encode(nonce),"process_profile_sha256":self.process_sha,"packet_sha256":profile.packet_sha256,"producer_profile_sha256":profile.producer_profile_sha256})).map_err(|_|())?;
        if metadata.len() > 4096 {
            return Err(());
        }
        channel::send(&incoming, &metadata, None)?;
        channel::send(&incoming, &self.raw, None)?;
        crate::supervision::ready(&incoming, Duration::from_secs(600))?;
        let (result, _) = channel::receive(&incoming, child.pid(), 4096, false)?;
        child.normal_exit(crate::supervision::CESSATION)?;
        admission_complete(&result, &nonce)
    }
}
fn admission_complete(raw: &[u8], nonce: &[u8; 32]) -> Result<()> {
    if raw.len() > 4096 {
        return Err(());
    }
    let value = crate::native_frame::read(raw)?;
    if value.as_object().ok_or(())?.len() != 3 {
        return Err(());
    }
    equal(
        &value,
        "schema",
        "heterodyne-owned-deployment-admission-result.v1",
    )?;
    equal(&value, "nonce_hex", &hex::encode(nonce))?;
    // Only the protected child's actual completed global journal is positive.
    // Failed-no-effect, unknown, cancelled and any future status remain HOLD.
    equal(&value, "status", "complete")
}

pub(crate) fn entry() -> Result<()> {
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0
        || unsafe { libc::getegid() } != 0
        || std::env::args_os().count() != 1
        || std::env::vars_os().next().is_some()
    {
        return Err(());
    }
    let originals = [3, 4, 5, 6, 7, 13, 14, 15, 18]
        .map(pins::inherited)
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let original = &originals[0];
    let lease = &originals[3];
    let packet = input::protected_bytes(&originals[8])?;
    let producer = input::protected_bytes(&originals[5])?;
    let p = input::profile(&input::protected_bytes(original)?)?;
    let m = lease.metadata().map_err(|_| ())?;
    if !m.is_file()
        || m.uid() != 0
        || m.gid() != 0
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
            != libc::O_RDWR
    {
        return Err(());
    }
    lease.try_lock().map_err(|_| ())?;
    let (admission, profile, bootstrap) = pins::profiles()?;
    if pins::sha(&packet) != profile.packet_sha256
        || pins::sha(&producer) != profile.producer_profile_sha256
        || p.installation.index_sha256 != profile.installation_index_sha256
        || p.installation.source_sha256().map_err(|_| ())? != profile.installation_source_sha256
    {
        return Err(());
    }
    let verified = p.installation.verify_host_parent().map_err(|_| ())?;
    let (nonce, nonce_file) = channel::nonce()?;
    let (incoming, outgoing) = crate::owner_entry::channel()?;
    crate::initializer_handoff::enable_credentials(&incoming).map_err(|_| ())?;
    let mut inputs = [3, 4, 5, 6, 7, 13, 14, 15, 18]
        .into_iter()
        .zip(originals.iter())
        .collect::<Vec<_>>();
    inputs.extend_from_slice(&[(8, &outgoing), (9, &nonce_file)]);
    let child = HostChild::bootstrap(&bootstrap, &inputs, lease.try_clone().map_err(|_| ())?)?;
    drop(inputs);
    drop(outgoing);
    let consumed = OwnedConsumedDeployment::accept(child, &incoming, nonce, &p, &profile, &packet)?;
    consumed.admission(
        &verified,
        &admission,
        &profile,
        lease,
        &[
            (13, &originals[5]),
            (14, &originals[6]),
            (15, &originals[7]),
            (18, &originals[8]),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "actual sealed root nonce domains"]
    fn receiver_nonce_does_not_approve_the_root_admission_domain() {
        let (bootstrap_nonce, _) = channel::nonce().unwrap();
        let (admission_nonce, admission_file) = channel::nonce().unwrap();
        assert_ne!(bootstrap_nonce, admission_nonce);
        assert_eq!(
            channel::read_nonce(&admission_file).unwrap(),
            admission_nonce
        );
        let response = |nonce| {
            serde_json::to_vec(&json!({
                "schema":"heterodyne-owned-deployment-admission-result.v1",
                "nonce_hex":hex::encode(nonce),"status":"complete"
            }))
            .unwrap()
        };
        assert!(admission_complete(&response(bootstrap_nonce), &admission_nonce).is_err());
        assert!(admission_complete(&response(admission_nonce), &admission_nonce).is_ok());
    }
    #[test]
    fn only_exact_bound_complete_is_positive() {
        let nonce = [7; 32];
        for status in [
            "complete",
            "failed-no-effect",
            "unknown",
            "cancelled",
            "future",
        ] {
            let mut value = json!({"schema":"heterodyne-owned-deployment-admission-result.v1", "nonce_hex":hex::encode(nonce), "status":status});
            let raw = serde_json::to_vec(&value).unwrap();
            assert_eq!(
                admission_complete(&raw, &nonce).is_ok(),
                status == "complete"
            );
            assert!(admission_complete(&raw, &[8; 32]).is_err());
            value["untrusted_extra"] = json!(true);
            assert!(admission_complete(&serde_json::to_vec(&value).unwrap(), &nonce).is_err());
        }
        assert!(
            admission_complete(b"{\"status\":\"complete\",\"status\":\"unknown\"}", &nonce)
                .is_err()
        );
    }
}
