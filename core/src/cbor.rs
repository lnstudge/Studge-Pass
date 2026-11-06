//! Small strict helpers on top of `ciborium::value::Value`.
//!
//! Every payload in Phase 3 is a CBOR map with a closed key set. The helpers
//! here make "reject unknown fields, duplicate keys and wrong types" the easy
//! path, so each parser is a list of expected keys rather than a match tree.

use crate::crypto::aad::parse_strict;
use crate::error::{CoreError, CoreResult};
use ciborium::value::Value;

/// Parses canonical CBOR and returns the map entries in encoded order.
///
/// Rejects a non-map, a non-text key and a duplicate key. Duplicates would
/// otherwise survive `parse_strict` (re-encoding a map with two equal keys can
/// reproduce the input) and let a parser read one value while a signer signed
/// another.
pub fn parse_map(bytes: &[u8]) -> CoreResult<Vec<(String, Value)>> {
    let value = parse_strict(bytes)?;
    let pairs = map_pairs(&value)?;
    Ok(pairs
        .into_iter()
        .map(|(name, value)| (name, value.clone()))
        .collect())
}

/// Returns the entries of an already-parsed CBOR map, rejecting a non-map, a
/// non-text key and a duplicate key.
pub fn map_pairs(value: &Value) -> CoreResult<Vec<(String, &Value)>> {
    let Value::Map(entries) = value else {
        return Err(CoreError::MalformedPayload);
    };
    let mut out: Vec<(String, &Value)> = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let Value::Text(name) = key else {
            return Err(CoreError::MalformedPayload);
        };
        if out.iter().any(|(existing, _)| existing == name) {
            return Err(CoreError::MalformedPayload);
        }
        out.push((name.clone(), value));
    }
    Ok(out)
}

/// Reads a text value.
pub fn as_text(value: &Value) -> CoreResult<&str> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(CoreError::MalformedPayload),
    }
}

/// Reads a byte string.
pub fn as_bytes(value: &Value) -> CoreResult<&[u8]> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(CoreError::MalformedPayload),
    }
}

/// Reads a non-negative integer that fits in `u64`.
pub fn as_u64(value: &Value) -> CoreResult<u64> {
    match value {
        Value::Integer(integer) => {
            let raw = i128::from(*integer);
            u64::try_from(raw).map_err(|_| CoreError::MalformedPayload)
        }
        _ => Err(CoreError::MalformedPayload),
    }
}

/// Reads a boolean.
pub fn as_bool(value: &Value) -> CoreResult<bool> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        _ => Err(CoreError::MalformedPayload),
    }
}

/// Reads an array of values.
pub fn as_array(value: &Value) -> CoreResult<&[Value]> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(CoreError::MalformedPayload),
    }
}

/// Reads an optional 16-byte id (`null` when absent).
pub fn as_id16(value: &Value) -> CoreResult<Option<[u8; 16]>> {
    match value {
        Value::Null => Ok(None),
        other => {
            let bytes = as_bytes(other)?;
            if bytes.len() != 16 {
                return Err(CoreError::InvalidLength {
                    expected: 16,
                    actual: bytes.len(),
                });
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(bytes);
            Ok(Some(id))
        }
    }
}

/// Reads a fixed-length 32-byte hash.
pub fn as_hash32(value: &Value) -> CoreResult<[u8; 32]> {
    let bytes = as_bytes(value)?;
    if bytes.len() != 32 {
        return Err(CoreError::InvalidLength {
            expected: 32,
            actual: bytes.len(),
        });
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(bytes);
    Ok(hash)
}

/// Builds a text value.
pub fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

/// Builds a byte-string value.
pub fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aad::{canonical_bytes, canonical_map};

    #[test]
    fn rejects_duplicate_and_non_text_keys() {
        let duplicate = Value::Map(vec![
            (text("a"), Value::Integer(1i64.into())),
            (text("a"), Value::Integer(2i64.into())),
        ]);
        let bytes = canonical_bytes(&duplicate).expect("encode");
        assert_eq!(
            parse_map(&bytes).expect_err("duplicate"),
            CoreError::MalformedPayload
        );

        let non_text = Value::Map(vec![(
            Value::Integer(1i64.into()),
            Value::Integer(1i64.into()),
        )]);
        let bytes = canonical_bytes(&non_text).expect("encode");
        assert_eq!(
            parse_map(&bytes).expect_err("key type"),
            CoreError::MalformedPayload
        );
    }

    #[test]
    fn reads_the_expected_types_only() {
        assert_eq!(as_text(&text("x")).expect("text"), "x");
        assert!(as_text(&Value::Bool(true)).is_err());
        assert_eq!(as_u64(&Value::Integer(7i64.into())).expect("uint"), 7);
        assert!(as_u64(&Value::Integer((-1i64).into())).is_err());
        assert!(as_id16(&Value::Null).expect("null id").is_none());
        assert!(!as_bool(&Value::Bool(false)).expect("bool"));
    }

    #[test]
    fn canonical_round_trip_survives_the_helper() {
        let value = canonical_map(vec![
            ("b", Value::Integer(2i64.into())),
            ("a", Value::Integer(1i64.into())),
        ]);
        let bytes = canonical_bytes(&value).expect("encode");
        let entries = parse_map(&bytes).expect("parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "a");
    }
}
