//! Closed, source-bound capability templates for future protected generations.
//! No startup schema selects the bounded template until generation composition.
use crate::{FeatureRegistry, key_package::KeyPackageMetadata};
use cgka_traits::{
    EngineError,
    agent_text_stream::{
        AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY, AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE,
        AgentTextStreamQuicPolicyV1,
    },
    app_components::{
        AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
        GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID, decode_encrypted_media_policy_v2,
    },
    capabilities::{CapabilityRequirement, RequirementLevel},
    group::ProtocolProfile,
};
use openmls::prelude::{Extension, MlsGroup};

/// A closed source template; its fields cannot be supplied by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Template {
    bounded: bool,
}
/// Original pinned routing support, independent of future generic defaults.
pub fn routing_only_v1() -> Template {
    Template { bounded: false }
}
/// Receive-only support. Publication still requires generation and functional gates.
pub fn bounded_app_receiver_v1() -> Template {
    Template { bounded: true }
}
impl Template {
    pub fn id(self) -> &'static str {
        if self.bounded {
            "bounded-app-receiver-v1"
        } else {
            "routing-only-v1"
        }
    }
    /// Exact reviewed policy bytes, independent of mutable Engine defaults.
    pub fn canonical_policy(self) -> Vec<u8> {
        let bounded = self.bounded;
        let components: Vec<u16> = self.components().into_iter().collect();
        let key_components = if bounded {
            vec![1, 0x8001, 0x8003, 0x8004, 0x8006, 0x8009, 0x800b, 0x800c]
        } else {
            vec![1, 0x8001, 0x8003, 0x8004, 0x8009, 0x800c]
        };
        let extensions = if bounded { vec![6, 0xf2d1] } else { vec![6] };
        let effective_extensions = if bounded {
            vec![1, 2, 3, 4, 5, 6, 0xf2d1]
        } else {
            vec![1, 2, 3, 4, 5, 6]
        };
        let features: Vec<&str> = if bounded {
            vec!["marmot.feature.agent_text_stream_quic.receive.v1"]
        } else {
            vec![]
        };
        let quic = if bounded {
            serde_json::json!({
                "required_roles": 1, "allowed_roles": 3, "max_plaintext_frame": 4096,
                "replay_ttl": 0, "padding": 0
            })
        } else {
            serde_json::Value::Null
        };
        serde_json::to_vec(&serde_json::json!({
            "schema": "heterodyne-receiver-capability-policy.v1", "template": self.id(),
            "protocol": "current", "component_inputs": components,
            "key_package_components": key_components, "mls_extensions": extensions,
            "mls_proposals": [8], "effective_extensions": effective_extensions,
            "effective_proposals": [1,2,3,4,5,6,7,8], "features": features,
            "quic": quic, "media": if bounded { "v2-validated-no-fetch" } else { "none" }
        }))
        .expect("closed integer policy is JSON serializable")
    }
    pub fn policy_sha256(self) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(self.canonical_policy()))
    }
    /// Exact closed policy selection; no capability lists or caller override.
    pub fn from_policy(id: &str, sha256: &str) -> Result<Self, EngineError> {
        let template = match id {
            "routing-only-v1" => routing_only_v1(),
            "bounded-app-receiver-v1" => bounded_app_receiver_v1(),
            _ => return Err(refused()),
        };
        if template.policy_sha256() != sha256 {
            return Err(refused());
        }
        Ok(template)
    }
    pub fn components(self) -> std::collections::BTreeSet<u16> {
        (if self.bounded {
            vec![0x8001, 0x8003, 0x8004, 0x8006, 0x800b, 0x800c]
        } else {
            vec![0x8001, 0x8003, 0x8004, 0x800c]
        })
        .into_iter()
        .collect()
    }
    pub fn registry(self) -> FeatureRegistry {
        let mut registry = FeatureRegistry::new();
        if self.bounded {
            registry.register(
                AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE.clone(),
                CapabilityRequirement {
                    requires: AGENT_TEXT_STREAM_QUIC_RECEIVE_CAPABILITY,
                    level: RequirementLevel::Optional,
                    description: "bounded protected receive-only stream support",
                },
            );
        }
        registry
    }
    pub fn validate_metadata(self, metadata: &KeyPackageMetadata) -> Result<(), EngineError> {
        let components = if self.bounded {
            vec![1, 0x8001, 0x8003, 0x8004, 0x8006, 0x8009, 0x800b, 0x800c]
        } else {
            vec![1, 0x8001, 0x8003, 0x8004, 0x8009, 0x800c]
        };
        let extensions = if self.bounded {
            vec![6, 0xf2d1]
        } else {
            vec![6]
        };
        if metadata.protocol_profile != ProtocolProfile::Current
            || metadata.ciphersuite != 1
            || metadata.app_components != components
            || metadata.mls_extensions != extensions
            || metadata.mls_proposals != [8]
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn validate_group(self, group: &MlsGroup) -> Result<(), EngineError> {
        // Old generations retain their original native policy. Their constructor
        // remains routing-only; this method introduces no retrospective narrowing.
        if !self.bounded {
            return Ok(());
        }
        if crate::account_identity_proof::protocol_profile_of_group(group)?
            != ProtocolProfile::Current
        {
            return Err(refused());
        }
        // Capabilities advertised by leaves do not authorize arbitrary live
        // GroupContext state. This closed Current template needs only these
        // two containers; QUIC policy remains dictionary component state.
        if group.extensions().iter().any(|extension| {
            !matches!(
                extension,
                Extension::RequiredCapabilities(_) | Extension::AppDataDictionary(_)
            )
        }) {
            return Err(refused());
        }
        let components = crate::app_components::required_app_components_of_group(group)?;
        let supported = [1, 0x8001, 0x8003, 0x8004, 0x8006, 0x8009, 0x800b, 0x800c];
        if components.ids.iter().any(|id| !supported.contains(id)) {
            return Err(refused());
        }
        // Optional dictionary state is authenticated too, but it must not widen
        // this closed template merely by omitting an ID from the required list.
        if group
            .extensions()
            .app_data_dictionary()
            .is_some_and(|dictionary| {
                dictionary
                    .dictionary()
                    .entries()
                    .any(|entry| !supported.contains(&entry.id()))
            })
        {
            return Err(refused());
        }
        let required = crate::capability_manager::required_capabilities_from_group(group);
        if required
            .extensions
            .iter()
            .any(|id| ![1, 2, 3, 4, 5, 6, 0xf2d1].contains(id))
            || required.proposals.iter().any(|id| !(1..=8).contains(id))
        {
            return Err(refused());
        }
        let data = |id| crate::app_components::app_component_data_of_group(group, id);
        if let Some(bytes) = data(AGENT_TEXT_STREAM_QUIC_COMPONENT_ID) {
            let policy = AgentTextStreamQuicPolicyV1::decode_component_state(&bytes)
                .map_err(|_| refused())?;
            // Values are pinned rather than taken from mutable app defaults.
            if policy.required_member_roles != 1
                || policy.allowed_member_roles != 3
                || policy.max_plaintext_frame_len != 4096
                || policy.replay_ttl_secs != 0
                || policy.padding_bucket_bytes != 0
            {
                return Err(refused());
            }
        }
        if data(GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID).is_some() {
            return Err(refused());
        }
        if let Some(bytes) = data(GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID) {
            decode_encrypted_media_policy_v2(&bytes).map_err(|_| refused())?;
        }
        Ok(())
    }
}
fn refused() -> EngineError {
    EngineError::Other("protected capability policy mismatch".into())
}
