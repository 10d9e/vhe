//! Core types and data structures

use num_bigint::BigUint;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Homomorphic encryption mode
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HomomorphicMode {
    /// Standard ElGamal - supports multiplication of plaintexts
    Multiplicative,
    /// Exponential ElGamal - supports addition of plaintexts (with limited message space)
    Additive,
}

impl fmt::Display for HomomorphicMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HomomorphicMode::Multiplicative => write!(f, "Multiplicative"),
            HomomorphicMode::Additive => write!(f, "Additive"),
        }
    }
}

/// ElGamal ciphertext (c1, c2)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) c1: BigUint,
    pub(crate) c2: BigUint,
    pub(crate) mode: HomomorphicMode,
}

impl Ciphertext {
    /// Create a new ciphertext
    pub fn new(c1: BigUint, c2: BigUint, mode: HomomorphicMode) -> Self {
        Ciphertext { c1, c2, mode }
    }

    /// Get the first component
    pub fn c1(&self) -> &BigUint {
        &self.c1
    }

    /// Get the second component
    pub fn c2(&self) -> &BigUint {
        &self.c2
    }

    /// Get the mode this ciphertext was encrypted in
    pub fn mode(&self) -> &HomomorphicMode {
        &self.mode
    }

    /// Get the size in bytes
    pub fn size_bytes(&self) -> usize {
        self.c1.to_bytes_be().len() + self.c2.to_bytes_be().len()
    }
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ciphertext({:?} mode, {} bytes)",
            self.mode,
            self.size_bytes()
        )
    }
}

/// Configuration for ElGamal operations
#[derive(Clone, Debug)]
pub struct ElGamalConfig {
    /// Maximum plaintext value for additive mode
    pub max_plaintext_additive: u64,
    /// Number of Miller-Rabin rounds for primality testing
    pub primality_test_rounds: usize,
    /// Whether to use safe primes (p = 2q + 1)
    pub use_safe_primes: bool,
}

impl Default for ElGamalConfig {
    fn default() -> Self {
        ElGamalConfig {
            max_plaintext_additive: 1_000_000,
            primality_test_rounds: 20,
            use_safe_primes: true,
        }
    }
}
