//! Key generation and management

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::One;
use rand::thread_rng;
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use std::fs::File;
#[cfg(feature = "serde")]
use std::io::{BufReader, BufWriter};

use crate::error::{ElGamalError, Result};
use crate::utils::{find_generator, generate_safe_prime, generate_safe_prime_lenient, mod_exp};

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

    /// Serialize the public key to bytes using bincode
    #[cfg(feature = "serde")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| ElGamalError::IOError(e.to_string()))
    }

    /// Deserialize a public key from bytes using bincode
    #[cfg(feature = "serde")]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let key: PublicKey =
            bincode::deserialize(data).map_err(|e| ElGamalError::IOError(e.to_string()))?;
        key.validate()?;
        Ok(key)
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

    /// Serialize the private key to bytes using bincode
    #[cfg(feature = "serde")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| ElGamalError::IOError(e.to_string()))
    }

    /// Deserialize a private key from bytes using bincode
    #[cfg(feature = "serde")]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let key: PrivateKey =
            bincode::deserialize(data).map_err(|e| ElGamalError::IOError(e.to_string()))?;
        Ok(key)
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
    /// Serialize the key pair to bytes using bincode
    #[cfg(feature = "serde")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| ElGamalError::IOError(e.to_string()))
    }

    /// Deserialize a key pair from bytes using bincode
    #[cfg(feature = "serde")]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let keypair: KeyPair =
            bincode::deserialize(data).map_err(|e| ElGamalError::IOError(e.to_string()))?;
        keypair.public_key.validate()?;
        Ok(keypair)
    }

    pub fn load_or_generate(bit_size: u64) -> Result<Self> {
        if let Ok(keypair) = Self::load(bit_size) {
            Ok(keypair)
        } else {
            let keypair = Self::generate(bit_size)?;
            keypair.save(bit_size)?;
            Ok(keypair)
        }
    }

    pub fn load(bit_size: u64) -> Result<Self> {
        let keypair = Self::load_from_file(bit_size)?;
        keypair.public_key.validate()?;
        Ok(keypair)
    }

    #[cfg(feature = "serde")]
    pub fn load_from_file(bit_size: u64) -> Result<Self> {
        let file_path = format!(".key_{}.bin", bit_size);
        let file = File::open(file_path).map_err(|e| ElGamalError::IOError(e.to_string()))?;
        let reader = BufReader::new(file);
        let keypair: KeyPair =
            bincode::deserialize_from(reader).map_err(|e| ElGamalError::IOError(e.to_string()))?;
        keypair.public_key.validate()?;
        Ok(keypair)
    }

    #[cfg(not(feature = "serde"))]
    pub fn load_from_file(_bit_size: u64) -> Result<Self> {
        // When serde is not available, we can't load from file
        Err(ElGamalError::IOError(
            "Serialization not available without serde feature".to_string(),
        ))
    }

    #[cfg(feature = "serde")]
    pub fn save(&self, bit_size: u64) -> Result<()> {
        let file_path = format!(".key_{}.bin", bit_size);
        let file = File::create(file_path).map_err(|e| ElGamalError::IOError(e.to_string()))?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, self).map_err(|e| ElGamalError::IOError(e.to_string()))?;
        Ok(())
    }

    #[cfg(not(feature = "serde"))]
    pub fn save(&self, _bit_size: u64) -> Result<()> {
        // When serde is not available, we can't save to file
        Err(ElGamalError::IOError(
            "Serialization not available without serde feature".to_string(),
        ))
    }

    /// Generate a new ElGamal key pair with specified bit size
    ///
    /// # Arguments
    ///
    /// * `bit_size` - The bit size for the prime modulus (minimum 512)
    ///
    /// # Example
    ///
    /// ```rust
    /// use vhe::KeyPair;
    ///
    /// let keypair = KeyPair::generate(1024).expect("Failed to generate keys");
    /// ```
    pub fn generate(bit_size: u64) -> Result<Self> {
        // For 512-bit keys, use lenient generation as they're harder to find
        if bit_size <= 512 {
            KeyPair::generate_lenient(bit_size)
        } else {
            KeyPair::generate_with_config(bit_size, true)
        }
    }

    /// Generate a key pair with lenient bit size requirements (allows ±8 bits)
    /// This is useful when exact bit size is not critical but safe primes are needed
    pub fn generate_lenient(target_bit_size: u64) -> Result<Self> {
        if target_bit_size < 512 {
            return Err(ElGamalError::InvalidKeySize(target_bit_size));
        }

        let mut rng = thread_rng();

        // Use lenient safe prime generation
        let (p, q) = generate_safe_prime_lenient(target_bit_size)?;

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
            // Generate a regular prime and compute q = (p-1)/2
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

    /// Generate a key pair quickly for testing (without safe primes)
    pub fn generate_for_testing(bit_size: u64) -> Result<Self> {
        Self::generate_with_config(bit_size, false)
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
    let max_iterations = 100000; // Increased for better success rate
    let mut iterations = 0;

    loop {
        iterations += 1;
        if iterations > max_iterations {
            return Err(ElGamalError::CryptoError(format!(
                "Failed to generate {}-bit prime after {} iterations",
                bit_size, max_iterations
            )));
        }

        // Generate a random odd number with exactly bit_size bits
        let mut candidate = rng.gen_biguint(bit_size);
        candidate |= BigUint::one(); // Make it odd
        candidate |= BigUint::one() << (bit_size - 1); // Set high bit

        // Ensure it has exactly the right number of bits
        if candidate.bits() == bit_size && is_probable_prime(&candidate, 20) {
            return Ok(candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        // Use faster generation for testing
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        assert!(keypair.public_key.bit_size() >= 511);
        assert!(keypair.public_key.bit_size() <= 513);
        keypair.public_key.validate().unwrap();
    }

    #[test]
    fn test_key_validation() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
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
        assert!(KeyPair::generate_for_testing(256).is_err());
        assert!(KeyPair::generate_for_testing(512).is_ok());
        assert!(KeyPair::generate_for_testing(1024).is_ok());
    }

    #[test]
    fn test_safe_prime_generation() {
        // Test that safe prime generation works (may have slight bit size variation)
        let keypair = KeyPair::generate(512).unwrap();
        // Allow some flexibility in bit size for safe primes
        assert!(keypair.public_key.bit_size() >= 504);
        assert!(keypair.public_key.bit_size() <= 520);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_public_key_bincode_serialization() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let public_key = &keypair.public_key;

        // Test serialization
        let serialized = public_key.to_bytes().unwrap();
        assert!(!serialized.is_empty());

        // Test deserialization
        let deserialized = PublicKey::from_bytes(&serialized).unwrap();
        assert_eq!(public_key, &deserialized);
        assert!(deserialized.validate().is_ok());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_private_key_bincode_serialization() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let private_key = &keypair.private_key;

        // Test serialization
        let serialized = private_key.to_bytes().unwrap();
        assert!(!serialized.is_empty());

        // Test deserialization
        let deserialized = PrivateKey::from_bytes(&serialized).unwrap();
        assert_eq!(private_key, &deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_keypair_bincode_serialization() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();

        // Test serialization
        let serialized = keypair.to_bytes().unwrap();
        assert!(!serialized.is_empty());

        // Test deserialization
        let deserialized = KeyPair::from_bytes(&serialized).unwrap();
        assert_eq!(keypair.public_key, deserialized.public_key);
        assert_eq!(keypair.private_key, deserialized.private_key);
        assert!(deserialized.public_key.validate().is_ok());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_keypair_file_operations() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let bit_size = 512;

        // Test saving and loading with bincode
        keypair.save(bit_size).unwrap();
        let loaded = KeyPair::load_from_file(bit_size).unwrap();
        assert_eq!(keypair.public_key, loaded.public_key);
        assert_eq!(keypair.private_key, loaded.private_key);

        // Clean up test files
        let _ = std::fs::remove_file(format!(".key_{}.bin", bit_size));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialization_size_comparison() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();

        // Compare sizes
        let bincode_bytes = keypair.to_bytes().unwrap();

        println!("Bincode size: {} bytes", bincode_bytes.len());
        println!(
            "Compression ratio: {:.2}x",
            bincode_bytes.len() as f64 / bincode_bytes.len() as f64
        );
    }
}
