//! Utility functions for Common Access Token

use crate::error::Error;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 signature
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC-SHA256 signature
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Error> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(signature)
        .map_err(|_| Error::SignatureVerification)
}

/// Get current timestamp in seconds since Unix epoch
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
