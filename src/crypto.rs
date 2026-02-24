//! Server-side cryptographic utilities.
//!
//! IMPORTANT: The heavy cryptographic lifting (E2EE, Double Ratchet, Sender Keys)
//! happens entirely on the CLIENT. The server is intentionally a "dumb relay" for
//! encrypted blobs.
//!
//! This module handles only server-side needs:
//! - Generating cryptographically secure random tokens
//! - Hashing (for token storage, not for encryption)
//! - Validating key format/length (not the keys' cryptographic properties)

use rand::Rng;

/// Minimum acceptable key length for X25519 public keys (32 bytes).
pub const X25519_KEY_LENGTH: usize = 32;

/// Validate that a public key is the correct length for X25519.
pub fn validate_x25519_key(key: &[u8]) -> bool {
    key.len() == X25519_KEY_LENGTH
}

/// Generate a cryptographically secure random byte vector.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen()).collect()
}

/// Generate a random invite code (URL-safe, 12 characters).
pub fn generate_invite_code() -> String {
    let bytes = random_bytes(9); // 9 bytes = 12 base64url chars
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
}

/// Determine the size bucket for an attachment (for metadata obfuscation).
/// Files are padded to these fixed sizes to prevent type inference from size.
pub fn size_bucket(actual_size: u64) -> i32 {
    match actual_size {
        0..=1_048_576 => 1,         // ≤1MB → bucket 1
        1_048_577..=5_242_880 => 5,  // ≤5MB → bucket 5
        5_242_881..=26_214_400 => 25, // ≤25MB → bucket 25
        _ => 100,                     // ≤100MB → bucket 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_x25519_key_correct_length() {
        assert!(validate_x25519_key(&[0u8; 32]));
    }

    #[test]
    fn validate_x25519_key_too_short() {
        assert!(!validate_x25519_key(&[0u8; 16]));
    }

    #[test]
    fn validate_x25519_key_too_long() {
        assert!(!validate_x25519_key(&[0u8; 64]));
    }

    #[test]
    fn validate_x25519_key_empty() {
        assert!(!validate_x25519_key(&[]));
    }

    #[test]
    fn random_bytes_returns_correct_length() {
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(16).len(), 16);
        assert_eq!(random_bytes(64).len(), 64);
    }

    #[test]
    fn random_bytes_are_not_all_zero() {
        // 32 random bytes should not all be zero (probability ~2^-256)
        let bytes = random_bytes(32);
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn generate_invite_code_is_12_chars() {
        let code = generate_invite_code();
        assert_eq!(code.len(), 12);
    }

    #[test]
    fn generate_invite_code_is_url_safe() {
        let code = generate_invite_code();
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn generate_invite_code_unique() {
        let a = generate_invite_code();
        let b = generate_invite_code();
        assert_ne!(a, b);
    }

    #[test]
    fn size_bucket_small_file() {
        assert_eq!(size_bucket(0), 1);
        assert_eq!(size_bucket(500_000), 1);
        assert_eq!(size_bucket(1_048_576), 1);
    }

    #[test]
    fn size_bucket_medium_file() {
        assert_eq!(size_bucket(1_048_577), 5);
        assert_eq!(size_bucket(5_242_880), 5);
    }

    #[test]
    fn size_bucket_large_file() {
        assert_eq!(size_bucket(5_242_881), 25);
        assert_eq!(size_bucket(26_214_400), 25);
    }

    #[test]
    fn size_bucket_very_large_file() {
        assert_eq!(size_bucket(26_214_401), 100);
        assert_eq!(size_bucket(100_000_000), 100);
    }
}
