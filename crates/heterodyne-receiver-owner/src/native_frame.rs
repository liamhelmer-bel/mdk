//! Native response structs use serde field order, not installation canonical JSON.
//! Preserve that ABI while rejecting duplicate keys, floats and trailing bytes.
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::fmt;
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("finite native JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    out.push(v);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some((k, Unique(v))) = map.next_entry::<String, Unique>()? {
                    if out.insert(k, v).is_some() {
                        return Err(de::Error::custom("duplicate native key"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub(crate) fn read(raw: &[u8]) -> Result<Value, ()> {
    if raw.is_empty() || raw.len() > crate::host_channel::MAX_NATIVE {
        return Err(());
    }
    serde_json::from_slice::<Unique>(raw)
        .map(|v| v.0)
        .map_err(|_| ())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consumed_frame_exact_engine_bound_is_finite() {
        let raw = serde_json::to_vec(
            &serde_json::json!({"text":"x".repeat(crate::host_channel::MAX_NATIVE-11)}),
        )
        .unwrap();
        assert_eq!(raw.len(), crate::host_channel::MAX_NATIVE);
        assert!(read(&raw).is_ok());
        let mut over = raw;
        over.push(b' ');
        assert!(read(&over).is_err());
    }
    #[test]
    fn actual_serde_struct_order_and_escape_abi_is_not_canonical_installation_json() {
        #[derive(serde::Serialize)]
        struct Native<'a> {
            schema: &'a str,
            nonce_hex: &'a str,
            text: &'a str,
        }
        let raw = serde_json::to_vec(&Native {
            schema: "result",
            nonce_hex: "abc",
            text: "a\nb",
        })
        .unwrap();
        assert!(receiver_installation_verifier::installation::parse_canonical(&raw).is_err());
        assert_eq!(read(&raw).unwrap()["text"], "a\nb");
        for raw in [
            br#"{"a":0,"a":1}"#.as_slice(),
            br#"{"b":{"a":0,"a":1}}"#,
            b"{}{}",
            b"1.0",
        ] {
            assert!(read(raw).is_err());
        }
    }
}
