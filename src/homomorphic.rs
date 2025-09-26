//! Homomorphic operations on ciphertexts

use num_bigint::BigUint;
use num_traits::One;

use crate::encryption::ElGamal;
use crate::error::{ElGamalError, Result};
use crate::types::{Ciphertext, HomomorphicMode};
use crate::utils::{mod_exp, mod_inverse};

/// Trait for homomorphic operations
pub trait HomomorphicOperations {
    /// Homomorphic operation (multiplication for multiplicative mode, addition for additive mode)
    fn homomorphic_operation(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext>;

    /// Scalar operation (scalar multiplication for multiplicative mode, scalar addition for additive mode)
    fn homomorphic_scalar_operation(&self, ct: &Ciphertext, scalar: &BigUint)
        -> Result<Ciphertext>;

    /// Homomorphic negation (for additive mode only)
    fn homomorphic_negate(&self, ct: &Ciphertext) -> Result<Ciphertext>;

    /// Homomorphic division (for multiplicative mode only)
    fn homomorphic_divide(
        &self,
        ct_numerator: &Ciphertext,
        ct_denominator: &Ciphertext,
    ) -> Result<Ciphertext>;

    /// Homomorphic subtraction (for additive mode only)
    fn homomorphic_subtract(&self, ct_a: &Ciphertext, ct_b: &Ciphertext) -> Result<Ciphertext>;

    /// Batch homomorphic operation on multiple ciphertexts
    fn homomorphic_batch_operation(&self, ciphertexts: &[Ciphertext]) -> Result<Ciphertext>;

    /// Compute linear combination in additive mode
    fn homomorphic_linear_combination(
        &self,
        ciphertexts: &[Ciphertext],
        coefficients: &[BigUint],
    ) -> Result<Ciphertext>;

    /// Helper: Encrypt a scalar and combine with existing ciphertext
    fn combine_with_scalar(&self, ct: &Ciphertext, scalar: &BigUint) -> Result<Ciphertext>;

    /// Homomorphic power/root operations for special cases
    fn homomorphic_root(&self, ct: &Ciphertext, k: &BigUint) -> Result<Ciphertext>;
}

impl HomomorphicOperations for ElGamal {
    fn homomorphic_operation(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        // Verify both ciphertexts are in the same mode
        if ct1.mode != ct2.mode {
            return Err(ElGamalError::MixedModes);
        }

        if ct1.mode != self.mode {
            return Err(ElGamalError::ModeMismatch {
                ciphertext_mode: ct1.mode.clone(),
                required_mode: self.mode.clone(),
            });
        }

        // The underlying operation is the same (component-wise multiplication)
        // But the semantic meaning differs based on mode
        let c1 = (&ct1.c1 * &ct2.c1) % &self.public_key.p;
        let c2 = (&ct1.c2 * &ct2.c2) % &self.public_key.p;

        Ok(Ciphertext::new(c1, c2, self.mode.clone()))
    }

    fn homomorphic_scalar_operation(
        &self,
        ct: &Ciphertext,
        scalar: &BigUint,
    ) -> Result<Ciphertext> {
        if ct.mode != self.mode {
            return Err(ElGamalError::ModeMismatch {
                ciphertext_mode: ct.mode.clone(),
                required_mode: self.mode.clone(),
            });
        }

        match self.mode {
            HomomorphicMode::Multiplicative => {
                // Raise ciphertext to power of scalar: Enc(m)^k = Enc(m^k)
                let c1 = mod_exp(&ct.c1, scalar, &self.public_key.p);
                let c2 = mod_exp(&ct.c2, scalar, &self.public_key.p);
                Ok(Ciphertext::new(c1, c2, HomomorphicMode::Multiplicative))
            }
            HomomorphicMode::Additive => {
                // Raise ciphertext to power of scalar: Enc(m)^k = Enc(m*k)
                let c1 = mod_exp(&ct.c1, scalar, &self.public_key.p);
                let c2 = mod_exp(&ct.c2, scalar, &self.public_key.p);
                Ok(Ciphertext::new(c1, c2, HomomorphicMode::Additive))
            }
        }
    }

    fn homomorphic_negate(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        if self.mode != HomomorphicMode::Additive {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.mode.clone(),
                operation: "negation".to_string(),
            });
        }

        if ct.mode != self.mode {
            return Err(ElGamalError::ModeMismatch {
                ciphertext_mode: ct.mode.clone(),
                required_mode: self.mode.clone(),
            });
        }

        // For negation, invert both components
        let c1_inv =
            mod_inverse(&ct.c1, &self.public_key.p).ok_or(ElGamalError::ModularInverseError)?;
        let c2_inv =
            mod_inverse(&ct.c2, &self.public_key.p).ok_or(ElGamalError::ModularInverseError)?;

        Ok(Ciphertext::new(c1_inv, c2_inv, HomomorphicMode::Additive))
    }

    fn homomorphic_divide(
        &self,
        ct_numerator: &Ciphertext,
        ct_denominator: &Ciphertext,
    ) -> Result<Ciphertext> {
        if self.mode != HomomorphicMode::Multiplicative {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.mode.clone(),
                operation: "division".to_string(),
            });
        }

        if ct_numerator.mode != self.mode || ct_denominator.mode != self.mode {
            return Err(ElGamalError::ModeMismatch {
                ciphertext_mode: ct_numerator.mode.clone(),
                required_mode: self.mode.clone(),
            });
        }

        // Division is multiplication by the modular inverse
        let c1_inv = mod_inverse(&ct_denominator.c1, &self.public_key.p)
            .ok_or(ElGamalError::ModularInverseError)?;
        let c2_inv = mod_inverse(&ct_denominator.c2, &self.public_key.p)
            .ok_or(ElGamalError::ModularInverseError)?;

        let c1 = (&ct_numerator.c1 * c1_inv) % &self.public_key.p;
        let c2 = (&ct_numerator.c2 * c2_inv) % &self.public_key.p;

        Ok(Ciphertext::new(c1, c2, HomomorphicMode::Multiplicative))
    }

    fn homomorphic_subtract(&self, ct_a: &Ciphertext, ct_b: &Ciphertext) -> Result<Ciphertext> {
        if self.mode != HomomorphicMode::Additive {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.mode.clone(),
                operation: "subtraction".to_string(),
            });
        }

        // Subtract by adding the negation: a - b = a + (-b)
        let ct_b_neg = self.homomorphic_negate(ct_b)?;
        self.homomorphic_operation(ct_a, &ct_b_neg)
    }

    fn homomorphic_batch_operation(&self, ciphertexts: &[Ciphertext]) -> Result<Ciphertext> {
        if ciphertexts.is_empty() {
            return Err(ElGamalError::EmptyBatch);
        }

        // Check all ciphertexts are in the correct mode
        for ct in ciphertexts {
            if ct.mode != self.mode {
                return Err(ElGamalError::ModeMismatch {
                    ciphertext_mode: ct.mode.clone(),
                    required_mode: self.mode.clone(),
                });
            }
        }

        // Start with the first ciphertext and accumulate the rest
        let mut result = ciphertexts[0].clone();
        for ct in &ciphertexts[1..] {
            result = self.homomorphic_operation(&result, ct)?;
        }

        Ok(result)
    }

    fn combine_with_scalar(&self, ct: &Ciphertext, scalar: &BigUint) -> Result<Ciphertext> {
        let ct_scalar = self.encrypt(scalar)?;
        self.homomorphic_operation(ct, &ct_scalar)
    }

    fn homomorphic_linear_combination(
        &self,
        ciphertexts: &[Ciphertext],
        coefficients: &[BigUint],
    ) -> Result<Ciphertext> {
        if self.mode != HomomorphicMode::Additive {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.mode.clone(),
                operation: "linear combination".to_string(),
            });
        }

        if ciphertexts.len() != coefficients.len() {
            return Err(ElGamalError::LengthMismatch(format!(
                "ciphertexts: {}, coefficients: {}",
                ciphertexts.len(),
                coefficients.len()
            )));
        }

        if ciphertexts.is_empty() {
            return Err(ElGamalError::EmptyBatch);
        }

        // Compute ai * ci for each term
        let mut terms = Vec::new();
        for (ct, coeff) in ciphertexts.iter().zip(coefficients.iter()) {
            terms.push(self.homomorphic_scalar_operation(ct, coeff)?);
        }

        // Sum all terms
        self.homomorphic_batch_operation(&terms)
    }

    fn homomorphic_root(&self, ct: &Ciphertext, k: &BigUint) -> Result<Ciphertext> {
        if ct.mode != self.mode {
            return Err(ElGamalError::ModeMismatch {
                ciphertext_mode: ct.mode.clone(),
                required_mode: self.mode.clone(),
            });
        }

        // This only works if k has a modular inverse mod (p-1)
        let p_minus_1 = &self.public_key.p - BigUint::one();
        let k_inv = mod_inverse(k, &p_minus_1).ok_or(ElGamalError::InvalidParameter(
            "Cannot compute root: k doesn't have an inverse mod (p-1)".to_string(),
        ))?;

        // Compute Enc(m)^(1/k) = Enc(m)^(k^(-1) mod (p-1))
        self.homomorphic_scalar_operation(ct, &k_inv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use num_bigint::ToBigUint;

    #[test]
    fn test_homomorphic_multiplication() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let m1 = 7u32.to_biguint().unwrap();
        let m2 = 6u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        let ct_product = elgamal.homomorphic_operation(&ct1, &ct2).unwrap();
        let decrypted = elgamal.decrypt(&ct_product, &keypair.private_key).unwrap();

        let expected = (m1 * m2) % keypair.public_key.p;
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_homomorphic_addition() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let m1 = 15u32.to_biguint().unwrap();
        let m2 = 25u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        let ct_sum = elgamal.homomorphic_operation(&ct1, &ct2).unwrap();
        let decrypted = elgamal.decrypt(&ct_sum, &keypair.private_key).unwrap();

        let expected = 40u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_batch_operations() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let values = vec![10u32, 20u32, 15u32];
        let ciphertexts: Vec<_> = values
            .iter()
            .map(|v| elgamal.encrypt(&v.to_biguint().unwrap()).unwrap())
            .collect();

        let ct_sum = elgamal.homomorphic_batch_operation(&ciphertexts).unwrap();
        let decrypted = elgamal.decrypt(&ct_sum, &keypair.private_key).unwrap();

        let expected = 45u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }
}
