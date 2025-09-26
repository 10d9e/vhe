//! Key generation and management

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::One;
use rand::thread_rng;
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::{ElGamalError, Result};
use crate::utils::{find_generator, generate_safe_prime, mod_exp};

/// ElGamal public key
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    pub(crate) p: BigUint, // Prime modulus
    pub(crate) g: BigUint, // Generator
    pub(crate) h: BigUint, // g^x mod p (public key component)
}

impl PublicKey {
    /// Create a new public key
    pub fn new(p: BigUint, g: BigUint, h: BigUint) -> Self {
        PublicKey { p, g, h }
    }

    /// Get the prime modulus
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }

    /// Get the generator
    pub fn generator(&self) -> &BigUint {
        &self.g
    }

    /// Get the public component (g^x mod p)
    pub fn public_component(&self) -> &BigUint {
        &self.h
    }

    /// Get the bit size of the modulus
    pub fn bit_size(&self) -> u64 {
        self.p.bits()
    }

    /// Validate the public key
    pub fn validate(&self) -> Result<()> {
        // Check that p > 2
        if self.p <= 2u32.to_biguint().unwrap() {
            return Err(ElGamalError::InvalidParameter(
                "Modulus p must be > 2".to_string(),
            ));
        }

        // Check that 1 < g < p
        if self.g <= BigUint::one() || self.g >= self.p {
            return Err(ElGamalError::InvalidParameter(
                "Generator g must be in range (1, p)".to_string(),
            ));
        }

        // Check that 1 < h < p
        if self.h <= BigUint::one() || self.h >= self.p {
            return Err(ElGamalError::InvalidParameter(
                "Public component h must be in range (1, p)".to_string(),
            ));
        }

        Ok(())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({} bits)", self.bit_size())
    }
}

/// ElGamal private key
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrivateKey {
    pub(crate) x: BigUint, // Secret exponent
}

impl PrivateKey {
    /// Create a new private key
    pub fn new(x: BigUint) -> Self {
        PrivateKey { x }
    }

    /// Get the secret exponent
    pub fn secret_exponent(&self) -> &BigUint {
        &self.x
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey(***)")
    }
}

/// ElGamal key pair
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Generate a new ElGamal key pair with specified bit size
    ///
    /// # Arguments
    ///
    /// * `bit_size` - The bit size for the prime modulus (minimum 512)
    ///
    /// # Example
    ///
    /// ```rust
    /// use elgamal_he::KeyPair;
    ///
    /// let keypair = KeyPair::generate(1024).expect("Failed to generate keys");
    /// assert_eq!(keypair.public_key.bit_size(), 1024);
    /// ```
    pub fn generate(bit_size: u64) -> Result<Self> {
        KeyPair::generate_with_config(bit_size, true)
    }

    /// Generate a key pair with optional safe prime usage
    pub fn generate_with_config(bit_size: u64, use_safe_prime: bool) -> Result<Self> {
        if bit_size < 512 {
            return Err(ElGamalError::InvalidKeySize(bit_size));
        }

        let mut rng = thread_rng();

        let (p, q) = if use_safe_prime {
            generate_safe_prime(bit_size)?
        } else {
            // For testing or when safe primes aren't required
            let p = generate_prime(bit_size)?;
            let q = (&p - 1u32) / 2u32;
            (p, q)
        };

        // Find a generator g
        let g = find_generator(&p, &q);

        // Generate private key x randomly from [1, p-2]
        let x = rng.gen_biguint_range(&BigUint::one(), &(&p - 2u32));

        // Compute public key h = g^x mod p
        let h = mod_exp(&g, &x, &p);

        let public_key = PublicKey { p, g, h };
        let private_key = PrivateKey { x };

        // Validate the generated keys
        public_key.validate()?;

        Ok(KeyPair {
            public_key,
            private_key,
        })
    }

    /// Create a key pair from existing components
    pub fn from_components(p: BigUint, g: BigUint, x: BigUint) -> Result<Self> {
        let h = mod_exp(&g, &x, &p);
        let public_key = PublicKey { p, g, h };
        let private_key = PrivateKey { x };

        public_key.validate()?;

        Ok(KeyPair {
            public_key,
            private_key,
        })
    }

    /// Get the bit size of the keys
    pub fn bit_size(&self) -> u64 {
        self.public_key.bit_size()
    }
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPair({} bits)", self.bit_size())
    }
}

/// Generate a prime number of the specified bit size (not necessarily safe)
fn generate_prime(bit_size: u64) -> Result<BigUint> {
    use crate::utils::is_probable_prime;

    let mut rng = thread_rng();
    let max_iterations = 10000;
    let mut iterations = 0;

    loop {
        iterations += 1;
        if iterations > max_iterations {
            return Err(ElGamalError::CryptoError(
                "Failed to generate prime after maximum iterations".to_string(),
            ));
        }

        let candidate = rng.gen_biguint(bit_size) | BigUint::one();

        if is_probable_prime(&candidate, 20) {
            return Ok(candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate(512).unwrap();
        assert!(keypair.public_key.bit_size() >= 511);
        assert!(keypair.public_key.bit_size() <= 513);
        keypair.public_key.validate().unwrap();
    }

    #[test]
    fn test_key_validation() {
        let keypair = KeyPair::generate(512).unwrap();
        assert!(keypair.public_key.validate().is_ok());

        // Test invalid public key
        let invalid_pk = PublicKey {
            p: 2u32.to_biguint().unwrap(),
            g: 1u32.to_biguint().unwrap(),
            h: 1u32.to_biguint().unwrap(),
        };
        assert!(invalid_pk.validate().is_err());
    }

    #[test]
    fn test_key_size_validation() {
        assert!(KeyPair::generate(256).is_err());
        assert!(KeyPair::generate(512).is_ok());
        assert!(KeyPair::generate(1024).is_ok());
    }
}
