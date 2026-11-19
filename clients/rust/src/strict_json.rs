use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::fmt;

// serde_json::Value normally keeps the last duplicate. Signed documents must have one interpretation.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                Number::from_f64(v)
                    .map(|n| Strict(n.into()))
                    .ok_or(E::custom("INVALID_JSON"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Strict(values.into()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(name) = map.next_key::<String>()? {
                    if values.contains_key(&name) {
                        return Err(de::Error::custom("DUPLICATE_PROPERTY"));
                    }
                    values.insert(name, map.next_value::<Strict>()?.0);
                }
                Ok(Strict(values.into()))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}
fn bounded(value: &Value, depth: usize) -> bool {
    depth <= 16
        && match value {
            Value::Array(values) => values.iter().all(|v| bounded(v, depth + 1)),
            Value::Object(values) => values.values().all(|v| bounded(v, depth + 1)),
            _ => true,
        }
}
pub fn parse(bytes: &[u8]) -> Result<Value, ()> {
    let Strict(value) = serde_json::from_slice(bytes).map_err(|_| ())?;
    if bounded(&value, 0) {
        Ok(value)
    } else {
        Err(())
    }
}
