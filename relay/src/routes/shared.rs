//! Small helpers shared by the route modules.

/// Base64 (standard alphabet, padding) for the OPAQUE fields in JSON bodies.
pub fn b64_encode(bytes: &[u8]) -> String {
    studge_core::codec::base64_encode(bytes)
}

/// Strict base64 with a length cap.
pub fn b64_decode(value: &str, max: usize) -> Result<Vec<u8>, crate::error::ApiError> {
    if value.len() > max {
        return Err(crate::error::ApiError::InvalidRequest);
    }
    studge_core::codec::base64_decode(value).map_err(|_| crate::error::ApiError::InvalidRequest)
}

/// Hex encoding for ids, hashes and tokens.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
