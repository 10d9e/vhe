//! # ElGamal Homomorphic Encryption Library
//!
//! This library provides a complete implementation of ElGamal encryption with:
//! - Multiplicative and additive homomorphic modes
//! - Non-interactive zero-knowledge proofs
//! - Verifiable operations
//!
//! ## Features
//!
//! - **Dual-mode operation**: Switch between multiplicative and additive homomorphism
//! - **Verifiable computation**: All operations can be verified with NIZK proofs
//! - **Batch operations**: Efficient processing of multiple ciphertexts
//! - **Re-randomization**: Generate different ciphertexts for the same plaintext
//!
//! ## Example
//!
//! ```rust
//! use vhe::{KeyPair, ElGamal, HomomorphicMode, HomomorphicOperations};
//!
//! // Generate keys
//! let keypair = KeyPair::generate(512).unwrap();
//!
//! // Create ElGamal instance for additive operations
//! let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);
//!
//! // Encrypt values
//! let ct1 = elgamal.encrypt(&10u32.into()).unwrap();
//! let ct2 = elgamal.encrypt(&20u32.into()).unwrap();
//!
//! // Perform homomorphic addition
//! let sum = elgamal.homomorphic_operation(&ct1, &ct2).unwrap();
//!
//! // Decrypt result
//! let result = elgamal.decrypt(&sum, &keypair.private_key).unwrap();
//! assert_eq!(result, 30u32.into());
//! ```

pub mod encryption;
pub mod error;
pub mod homomorphic;
pub mod keys;
pub mod proofs;
pub mod types;
pub mod utils;

// Re-export main types for convenience
pub use encryption::ElGamal;
pub use error::{ElGamalError, Result};
pub use homomorphic::HomomorphicOperations;
pub use keys::{KeyPair, PrivateKey, PublicKey};
pub use proofs::{
    ProofOfCorrectEncryption, ProofOfCorrectOperation, ProofOfEquality, ProofOfKnowledge,
    ProofOfReRandomization, VerifiableOperations,
};
pub use types::{Ciphertext, HomomorphicMode};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;

    #[test]
    fn test_library_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_basic_workflow() {
        let keypair = KeyPair::generate_for_testing(512);
        assert!(keypair.is_ok());

        let keypair = keypair.unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let m = 42u32.to_biguint().unwrap();
        let ct = elgamal.encrypt(&m).unwrap();
        let decrypted = elgamal.decrypt(&ct, &keypair.private_key).unwrap();

        assert_eq!(m, decrypted);
    }
}
