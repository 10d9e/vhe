//! Error types for the ElGamal library

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ElGamalError>;

#[derive(Error, Debug)]
pub enum ElGamalError {
    #[error("Invalid key size: {0} bits (must be at least 512)")]
    InvalidKeySize(u64),

    #[error("Plaintext too large for modulus")]
    PlaintextTooLarge,

    #[error("Plaintext too large for additive mode: max is {max}")]
    PlaintextTooLargeForAdditive { max: u64 },

    #[error(
        "Mode mismatch: ciphertext is {ciphertext_mode:?} but operation requires {required_mode:?}"
    )]
    ModeMismatch {
        ciphertext_mode: crate::types::HomomorphicMode,
        required_mode: crate::types::HomomorphicMode,
    },

    #[error("Ciphertexts have different modes")]
    MixedModes,

    #[error("Failed to compute modular inverse")]
    ModularInverseError,

    #[error("Failed to solve discrete logarithm: {0}")]
    DiscreteLogError(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Empty list provided for batch operation")]
    EmptyBatch,

    #[error("Mismatched lengths: {0}")]
    LengthMismatch(String),

    #[error("Operation not supported in {mode:?} mode: {operation}")]
    UnsupportedOperation {
        mode: crate::types::HomomorphicMode,
        operation: String,
    },

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("IO error: {0}")]
    IOError(String),
}
