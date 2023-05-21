//! All the constants used in Matter.
//! Some constants are configured based on features such as
//! device capability.

/// The minimum number of PBKDF iterations used,
pub const MIN_PBKDF_ITERATIONS: usize = 1000;
pub const MAX_PBKDF_ITERATIONS: usize = 100000;
pub const PBKDF_ITERATIONS: usize = 1000;
pub const SHA256_HASH_LEN_BYTES: usize = 32;
pub const EC_SIGNATURE_LEN_BYTES: usize = 64;
pub const SPAKE2P_CONTEXT_PREFIX: [u8; 26] = *b"CHIP PAKE V1 Commissioning";
pub const SPAKE2P_KEY_CONFIRM_INFO: [u8; 16] = *b"ConfirmationKeys";
pub const SESSION_KEYS_INFO: [u8; 11] = *b"SessionKeys";
pub const SESSION_RESUMPTION_KEYS_INFO: [u8; 21] = *b"SessionResumptionKeys";

pub const CRYPTO_SYMMETRIC_KEY_LENGTH_BITS: usize = 128;
pub const CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: usize = CRYPTO_SYMMETRIC_KEY_LENGTH_BITS / 8;
// ...
pub const CRYPTO_AEAD_MIC_LENGTH_BITS: usize = 128;
pub const CRYPTO_AEAD_MIC_LENGTH_BYTES: usize = CRYPTO_AEAD_MIC_LENGTH_BITS / 8;
pub const CRYPTO_AEAD_NONCE_LENGTH_BYTES: usize = 13;
