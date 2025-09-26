//! Core ElGamal encryption and decryption operations

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::One;
use rand::thread_rng;
use std::collections::HashMap;

use crate::error::{ElGamalError, Result};
use crate::keys::{PrivateKey, PublicKey};
use crate::types::{Ciphertext, ElGamalConfig, HomomorphicMode};
use crate::utils::{mod_exp, mod_inverse};

/// ElGamal homomorphic encryption system
#[derive(Clone, Debug)]
pub struct ElGamal {
    pub public_key: PublicKey,
    pub(crate) mode: HomomorphicMode,
    pub(crate) dlog_table: Option<HashMap<BigUint, u64>>,
    pub(crate) max_plaintext: u64,
    config: ElGamalConfig,
}

impl ElGamal {
    /// Create a new ElGamal instance with specified mode
    pub fn new(public_key: PublicKey, mode: HomomorphicMode) -> Self {
        Self::with_config(public_key, mode, ElGamalConfig::default())
    }

    /// Create a new ElGamal instance with custom configuration
    pub fn with_config(
        public_key: PublicKey,
        mode: HomomorphicMode,
        config: ElGamalConfig,
    ) -> Self {
        let (dlog_table, max_plaintext) = if mode == HomomorphicMode::Additive {
            let table =
                Self::build_dlog_table(&public_key.g, &public_key.p, config.max_plaintext_additive);
            (Some(table), config.max_plaintext_additive)
        } else {
            (None, 0)
        };

        ElGamal {
            public_key,
            mode,
            dlog_table,
            max_plaintext,
            config,
        }
    }

    /// Get the current homomorphic mode
    pub fn mode(&self) -> &HomomorphicMode {
        &self.mode
    }

    /// Get the configuration
    pub fn config(&self) -> &ElGamalConfig {
        &self.config
    }

    /// Build discrete log lookup table for additive mode (baby-step giant-step)
    fn build_dlog_table(g: &BigUint, p: &BigUint, max_val: u64) -> HashMap<BigUint, u64> {
        let mut table = HashMap::new();
        let mut current = BigUint::one();

        // Build table: g^i mod p for i = 0 to max_val
        for i in 0..=max_val {
            table.insert(current.clone(), i);
            current = (&current * g) % p;
        }

        table
    }

    /// Solve discrete log using baby-step giant-step algorithm
    pub(crate) fn solve_discrete_log(&self, value: &BigUint) -> Result<u64> {
        if let Some(ref table) = self.dlog_table {
            // Try direct lookup first
            if let Some(&result) = table.get(value) {
                return Ok(result);
            }

            // Baby-step giant-step for larger values
            let m = ((self.max_plaintext as f64).sqrt() as u64) + 1;
            let gm = mod_exp(
                &self.public_key.g,
                &m.to_biguint().unwrap(),
                &self.public_key.p,
            );
            let gm_inv =
                mod_inverse(&gm, &self.public_key.p).ok_or(ElGamalError::ModularInverseError)?;

            let mut gamma = value.clone();
            for j in 0..m {
                if let Some(&i) = table.get(&gamma) {
                    return Ok(j * m + i);
                }
                gamma = (&gamma * &gm_inv) % &self.public_key.p;
            }

            Err(ElGamalError::DiscreteLogError(
                "Could not solve discrete log - value too large".to_string(),
            ))
        } else {
            Err(ElGamalError::DiscreteLogError(
                "Discrete log table not available".to_string(),
            ))
        }
    }

    /// Encrypt a plaintext message
    pub fn encrypt(&self, plaintext: &BigUint) -> Result<Ciphertext> {
        self.encrypt_with_randomness(plaintext, None)
    }

    /// Encrypt with specific randomness (for testing or proof generation)
    pub fn encrypt_with_randomness(
        &self,
        plaintext: &BigUint,
        randomness: Option<BigUint>,
    ) -> Result<Ciphertext> {
        match self.mode {
            HomomorphicMode::Multiplicative => {
                if plaintext >= &self.public_key.p {
                    return Err(ElGamalError::PlaintextTooLarge);
                }

                let mut rng = thread_rng();
                let k = randomness.unwrap_or_else(|| {
                    rng.gen_biguint_range(&BigUint::one(), &(&self.public_key.p - 2u32))
                });

                let c1 = mod_exp(&self.public_key.g, &k, &self.public_key.p);
                let h_k = mod_exp(&self.public_key.h, &k, &self.public_key.p);
                let c2 = (plaintext * h_k) % &self.public_key.p;

                Ok(Ciphertext::new(c1, c2, HomomorphicMode::Multiplicative))
            }
            HomomorphicMode::Additive => {
                if plaintext > &self.max_plaintext.to_biguint().unwrap() {
                    return Err(ElGamalError::PlaintextTooLargeForAdditive {
                        max: self.max_plaintext,
                    });
                }

                let mut rng = thread_rng();
                let k = randomness.unwrap_or_else(|| {
                    rng.gen_biguint_range(&BigUint::one(), &(&self.public_key.p - 2u32))
                });

                let c1 = mod_exp(&self.public_key.g, &k, &self.public_key.p);

                // Encode message in exponent: g^m
                let g_m = mod_exp(&self.public_key.g, plaintext, &self.public_key.p);
                let h_k = mod_exp(&self.public_key.h, &k, &self.public_key.p);
                let c2 = (g_m * h_k) % &self.public_key.p;

                Ok(Ciphertext::new(c1, c2, HomomorphicMode::Additive))
            }
        }
    }

    /// Decrypt a ciphertext using the private key
    pub fn decrypt(&self, ciphertext: &Ciphertext, private_key: &PrivateKey) -> Result<BigUint> {
        // Verify mode matches
        if ciphertext.mode != self.mode {
            return Err(ElGamalError::ModeMismatch {
                ciphertext_mode: ciphertext.mode.clone(),
                required_mode: self.mode.clone(),
            });
        }

        let s = mod_exp(&ciphertext.c1, &private_key.x, &self.public_key.p);
        let s_inv = mod_inverse(&s, &self.public_key.p).ok_or(ElGamalError::ModularInverseError)?;

        match self.mode {
            HomomorphicMode::Multiplicative => {
                // Standard decryption: m = c2 * s^-1 mod p
                Ok((ciphertext.c2.clone() * s_inv) % &self.public_key.p)
            }
            HomomorphicMode::Additive => {
                // Exponential ElGamal: recover g^m, then solve discrete log
                let g_m = (ciphertext.c2.clone() * s_inv) % &self.public_key.p;
                self.solve_discrete_log(&g_m)
                    .map(|m| m.to_biguint().unwrap())
            }
        }
    }

    /// Re-randomize a ciphertext (produces a different encryption of the same plaintext)
    pub fn rerandomize(&self, ciphertext: &Ciphertext) -> Result<Ciphertext> {
        if ciphertext.mode != self.mode {
            return Err(ElGamalError::ModeMismatch {
                ciphertext_mode: ciphertext.mode.clone(),
                required_mode: self.mode.clone(),
            });
        }

        let mut rng = thread_rng();
        let r = rng.gen_biguint_range(&BigUint::one(), &(&self.public_key.p - 2u32));

        let g_r = mod_exp(&self.public_key.g, &r, &self.public_key.p);
        let c1 = (&ciphertext.c1 * g_r) % &self.public_key.p;

        let h_r = mod_exp(&self.public_key.h, &r, &self.public_key.p);
        let c2 = (&ciphertext.c2 * h_r) % &self.public_key.p;

        Ok(Ciphertext::new(c1, c2, self.mode.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_encryption_decryption() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let plaintext = 42u32.to_biguint().unwrap();
        let ciphertext = elgamal.encrypt(&plaintext).unwrap();
        let decrypted = elgamal.decrypt(&ciphertext, &keypair.private_key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_additive_mode() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let plaintext = 100u32.to_biguint().unwrap();
        let ciphertext = elgamal.encrypt(&plaintext).unwrap();
        let decrypted = elgamal.decrypt(&ciphertext, &keypair.private_key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_rerandomization() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let plaintext = 42u32.to_biguint().unwrap();
        let ct1 = elgamal.encrypt(&plaintext).unwrap();
        let ct2 = elgamal.rerandomize(&ct1).unwrap();

        // Ciphertexts should be different
        assert_ne!(ct1, ct2);

        // But decrypt to the same plaintext
        let dec1 = elgamal.decrypt(&ct1, &keypair.private_key).unwrap();
        let dec2 = elgamal.decrypt(&ct2, &keypair.private_key).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(plaintext, dec1);
    }
}
