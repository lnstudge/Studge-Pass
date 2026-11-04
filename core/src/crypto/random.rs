//! The single source of randomness for core.
//!
//! SPEC §4 and AGENTS.md rule 3: every nonce, key and identifier comes from the
//! operating system's `OsRng`. There is no software fallback and no seeded
//! generator in production code; a failure is returned to the caller and the
//! operation aborts.

use crate::crypto::error::{CryptoError, CryptoResult};

/// Fills `dst` with bytes from the operating system's random source.
pub fn fill(dst: &mut [u8]) -> CryptoResult<()> {
    getrandom::fill(dst).map_err(|_| CryptoError::RngFailure)
}

/// Returns `N` random bytes from the operating system's random source.
pub fn array<const N: usize>() -> CryptoResult<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_without_error() {
        let mut buf = [0u8; 64];
        fill(&mut buf).expect("OsRng should be available in tests");
        assert_ne!(buf, [0u8; 64], "64 zero bytes would be a broken RNG");
    }

    #[test]
    fn two_draws_differ() {
        let a: [u8; 32] = array().expect("OsRng available");
        let b: [u8; 32] = array().expect("OsRng available");
        assert_ne!(a, b);
    }
}
