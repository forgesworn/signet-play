//! Small value guards shared by the parsers — the Rust spelling of upstream's
//! `isHex` and of JavaScript's `Number.isInteger` / `Number.isSafeInteger`
//! over a `JSON.parse`d value.

use serde_json::Value;

/// `isHex(value, length)`: lowercase hex, exactly `len` characters, even length.
pub fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && len > 0
        && len.is_multiple_of(2)
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `is_hex` over a JSON value: must be a string first.
pub fn json_hex(value: Option<&Value>, len: usize) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| is_hex(s, len))
}

/// A non-negative JSON integer. Accepts `2.0` as `2`, as `Number.isInteger`
/// does; refuses fractions, negatives and non-numbers.
pub fn js_uint(value: Option<&Value>) -> Option<u64> {
    let v = value?;
    if let Some(u) = v.as_u64() {
        return Some(u);
    }
    let f = v.as_f64()?;
    if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= u64::MAX as f64 {
        Some(f as u64)
    } else {
        None
    }
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// `Number.isSafeInteger(v) && v >= 0`.
pub fn js_safe_uint(value: Option<&Value>) -> Option<u64> {
    js_uint(value).filter(|n| *n <= MAX_SAFE_INTEGER)
}

/// Whether a key is present on the wire in the `o[k] !== undefined` sense:
/// a JSON `null` counts as present.
pub fn has(obj: &serde_json::Map<String, Value>, key: &str) -> bool {
    obj.contains_key(key)
}
