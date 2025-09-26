//! Homomorphic operations on ciphertexts

use num_bigint::BigUint;
use num_traits::One;
use std::ops::{Add, Div, Mul, Neg, Sub};

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

/// Wrapper for ElGamal that enables operator overrides
/// This allows using standard operators like +, -, *, / on ciphertexts
#[derive(Clone, Debug)]
pub struct HomomorphicElGamal {
    elgamal: ElGamal,
}

impl HomomorphicElGamal {
    /// Create a new HomomorphicElGamal wrapper
    pub fn new(elgamal: ElGamal) -> Self {
        Self { elgamal }
    }

    /// Get the underlying ElGamal instance
    pub fn inner(&self) -> &ElGamal {
        &self.elgamal
    }

    /// Get a mutable reference to the underlying ElGamal instance
    pub fn inner_mut(&mut self) -> &mut ElGamal {
        &mut self.elgamal
    }

    /// Encrypt a plaintext
    pub fn encrypt(&self, plaintext: &BigUint) -> Result<Ciphertext> {
        self.elgamal.encrypt(plaintext)
    }

    /// Decrypt a ciphertext
    pub fn decrypt(
        &self,
        ciphertext: &Ciphertext,
        private_key: &crate::keys::PrivateKey,
    ) -> Result<BigUint> {
        self.elgamal.decrypt(ciphertext, private_key)
    }
}

// Operator implementations for Ciphertext + Ciphertext
impl Add<&Ciphertext> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn add(self, _rhs: &Ciphertext) -> Self::Output {
        // We need access to the ElGamal instance to perform operations
        // This is a limitation of the operator trait approach
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

impl Sub<&Ciphertext> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn sub(self, _rhs: &Ciphertext) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

impl Mul<&Ciphertext> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn mul(self, _rhs: &Ciphertext) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

impl Div<&Ciphertext> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn div(self, _rhs: &Ciphertext) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

impl Neg for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn neg(self) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

// Operator implementations for Ciphertext + BigUint (scalar operations)
impl Add<&BigUint> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn add(self, _rhs: &BigUint) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

impl Sub<&BigUint> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn sub(self, _rhs: &BigUint) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

impl Mul<&BigUint> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn mul(self, _rhs: &BigUint) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

impl Div<&BigUint> for &Ciphertext {
    type Output = Result<Ciphertext>;

    fn div(self, _rhs: &BigUint) -> Self::Output {
        Err(ElGamalError::InvalidParameter(
            "Operator overrides require HomomorphicElGamal wrapper. Use HomomorphicElGamal::new() to create a wrapper.".to_string()
        ))
    }
}

// Better approach: Implement operators on HomomorphicElGamal that take ciphertexts
impl HomomorphicElGamal {
    /// Add two ciphertexts (semantic meaning depends on mode)
    pub fn add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        self.elgamal.homomorphic_operation(ct1, ct2)
    }

    /// Subtract two ciphertexts (additive mode only)
    pub fn sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        self.elgamal.homomorphic_subtract(ct1, ct2)
    }

    /// Multiply two ciphertexts (semantic meaning depends on mode)
    pub fn mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        self.elgamal.homomorphic_operation(ct1, ct2)
    }

    /// Divide two ciphertexts (multiplicative mode only)
    pub fn div(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        self.elgamal.homomorphic_divide(ct1, ct2)
    }

    /// Negate a ciphertext (additive mode only)
    pub fn neg(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        self.elgamal.homomorphic_negate(ct)
    }

    /// Scalar addition (additive mode only)
    pub fn add_scalar(&self, ct: &Ciphertext, scalar: &BigUint) -> Result<Ciphertext> {
        if self.elgamal.mode != HomomorphicMode::Additive {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.elgamal.mode.clone(),
                operation: "scalar addition".to_string(),
            });
        }
        self.elgamal.combine_with_scalar(ct, scalar)
    }

    /// Scalar subtraction (additive mode only)
    pub fn sub_scalar(&self, ct: &Ciphertext, scalar: &BigUint) -> Result<Ciphertext> {
        if self.elgamal.mode != HomomorphicMode::Additive {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.elgamal.mode.clone(),
                operation: "scalar subtraction".to_string(),
            });
        }
        let ct_scalar = self.elgamal.encrypt(scalar)?;
        let ct_scalar_neg = self.elgamal.homomorphic_negate(&ct_scalar)?;
        self.elgamal.homomorphic_operation(ct, &ct_scalar_neg)
    }

    /// Scalar multiplication (both modes)
    pub fn mul_scalar(&self, ct: &Ciphertext, scalar: &BigUint) -> Result<Ciphertext> {
        self.elgamal.homomorphic_scalar_operation(ct, scalar)
    }

    /// Scalar division (multiplicative mode only)
    pub fn div_scalar(&self, ct: &Ciphertext, scalar: &BigUint) -> Result<Ciphertext> {
        if self.elgamal.mode != HomomorphicMode::Multiplicative {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.elgamal.mode.clone(),
                operation: "scalar division".to_string(),
            });
        }
        let ct_scalar = self.elgamal.encrypt(scalar)?;
        self.elgamal.homomorphic_divide(ct, &ct_scalar)
    }
}

// Alternative approach: Create a CiphertextWithContext that holds the ElGamal reference
/// A ciphertext with context that enables operator overrides
#[derive(Clone, Debug)]
pub struct CiphertextWithContext<'a> {
    ciphertext: Ciphertext,
    elgamal: &'a ElGamal,
}

impl<'a> CiphertextWithContext<'a> {
    /// Create a new CiphertextWithContext
    pub fn new(ciphertext: Ciphertext, elgamal: &'a ElGamal) -> Self {
        Self {
            ciphertext,
            elgamal,
        }
    }

    /// Get the underlying ciphertext
    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    /// Convert back to Ciphertext
    pub fn into_ciphertext(self) -> Ciphertext {
        self.ciphertext
    }
}

// Operator implementations for CiphertextWithContext
impl<'a> Add<&CiphertextWithContext<'a>> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn add(self, rhs: &CiphertextWithContext<'a>) -> Self::Output {
        self.elgamal
            .homomorphic_operation(&self.ciphertext, &rhs.ciphertext)
    }
}

impl<'a> Sub<&CiphertextWithContext<'a>> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn sub(self, rhs: &CiphertextWithContext<'a>) -> Self::Output {
        self.elgamal
            .homomorphic_subtract(&self.ciphertext, &rhs.ciphertext)
    }
}

impl<'a> Mul<&CiphertextWithContext<'a>> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn mul(self, rhs: &CiphertextWithContext<'a>) -> Self::Output {
        self.elgamal
            .homomorphic_operation(&self.ciphertext, &rhs.ciphertext)
    }
}

impl<'a> Div<&CiphertextWithContext<'a>> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn div(self, rhs: &CiphertextWithContext<'a>) -> Self::Output {
        self.elgamal
            .homomorphic_divide(&self.ciphertext, &rhs.ciphertext)
    }
}

impl<'a> Neg for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn neg(self) -> Self::Output {
        self.elgamal.homomorphic_negate(&self.ciphertext)
    }
}

// Scalar operations for CiphertextWithContext
impl<'a> Add<&BigUint> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn add(self, rhs: &BigUint) -> Self::Output {
        if self.elgamal.mode != HomomorphicMode::Additive {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.elgamal.mode.clone(),
                operation: "scalar addition".to_string(),
            });
        }
        self.elgamal.combine_with_scalar(&self.ciphertext, rhs)
    }
}

impl<'a> Sub<&BigUint> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn sub(self, rhs: &BigUint) -> Self::Output {
        if self.elgamal.mode != HomomorphicMode::Additive {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.elgamal.mode.clone(),
                operation: "scalar subtraction".to_string(),
            });
        }
        let ct_scalar = self.elgamal.encrypt(rhs)?;
        let ct_scalar_neg = self.elgamal.homomorphic_negate(&ct_scalar)?;
        self.elgamal
            .homomorphic_operation(&self.ciphertext, &ct_scalar_neg)
    }
}

impl<'a> Mul<&BigUint> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn mul(self, rhs: &BigUint) -> Self::Output {
        self.elgamal
            .homomorphic_scalar_operation(&self.ciphertext, rhs)
    }
}

impl<'a> Div<&BigUint> for &CiphertextWithContext<'a> {
    type Output = Result<Ciphertext>;

    fn div(self, rhs: &BigUint) -> Self::Output {
        if self.elgamal.mode != HomomorphicMode::Multiplicative {
            return Err(ElGamalError::UnsupportedOperation {
                mode: self.elgamal.mode.clone(),
                operation: "scalar division".to_string(),
            });
        }
        let ct_scalar = self.elgamal.encrypt(rhs)?;
        self.elgamal
            .homomorphic_divide(&self.ciphertext, &ct_scalar)
    }
}

// Extension trait to add operator methods to ElGamal
pub trait ElGamalOperators {
    /// Wrap ciphertext with context for operator overrides
    fn wrap_ciphertext(&self, ciphertext: Ciphertext) -> CiphertextWithContext<'_>;

    /// Create a HomomorphicElGamal wrapper
    fn into_homomorphic(self) -> HomomorphicElGamal;
}

impl ElGamalOperators for ElGamal {
    fn wrap_ciphertext(&self, ciphertext: Ciphertext) -> CiphertextWithContext<'_> {
        CiphertextWithContext::new(ciphertext, self)
    }

    fn into_homomorphic(self) -> HomomorphicElGamal {
        HomomorphicElGamal::new(self)
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

    #[test]
    fn test_ciphertext_with_context_operators() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let m1 = 5u32.to_biguint().unwrap();
        let m2 = 3u32.to_biguint().unwrap();
        let scalar = 2u32.to_biguint().unwrap();
        let p = &elgamal.public_key.p;

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Wrap ciphertexts with context
        let ctx1 = elgamal.wrap_ciphertext(ct1);
        let ctx2 = elgamal.wrap_ciphertext(ct2);

        // Test addition: ct1 + ct2
        let ct_sum = (&ctx1 + &ctx2).unwrap();
        let decrypted_sum = elgamal.decrypt(&ct_sum, &keypair.private_key).unwrap();
        assert_eq!(&m1 + &m2, decrypted_sum);

        // Test subtraction: ct1 - ct2
        let ct_diff = (&ctx1 - &ctx2).unwrap();
        let decrypted_diff = elgamal.decrypt(&ct_diff, &keypair.private_key).unwrap();
        assert_eq!((&m1 + p - &m2) % p, decrypted_diff);

        // Test scalar addition: ct1 + scalar
        let ct_scalar_add = (&ctx1 + &scalar).unwrap();
        let decrypted_scalar_add = elgamal
            .decrypt(&ct_scalar_add, &keypair.private_key)
            .unwrap();
        assert_eq!((&m1 + &scalar) % p, decrypted_scalar_add);

        // Test scalar subtraction: ct1 - scalar
        let ct_scalar_sub = (&ctx1 - &scalar).unwrap();
        let decrypted_scalar_sub = elgamal
            .decrypt(&ct_scalar_sub, &keypair.private_key)
            .unwrap();
        assert_eq!((&m1 + p - &scalar) % p, decrypted_scalar_sub);

        // Test scalar multiplication: ct1 * scalar
        let ct_scalar_mul = (&ctx1 * &scalar).unwrap();
        let decrypted_scalar_mul = elgamal
            .decrypt(&ct_scalar_mul, &keypair.private_key)
            .unwrap();
        assert_eq!((&m1 * &scalar) % p, decrypted_scalar_mul);

        // Test negation: -ct1
        let ct_neg = (-&ctx1).unwrap();
        let decrypted_neg = elgamal.decrypt(&ct_neg, &keypair.private_key).unwrap();
        assert_eq!((p - &m1) % p, decrypted_neg);
    }

    #[test]
    fn test_multiplicative_mode_operators() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let m1 = 7u32.to_biguint().unwrap();
        let m2 = 6u32.to_biguint().unwrap();
        let scalar = 3u32.to_biguint().unwrap();
        let p = &elgamal.public_key.p;

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Wrap ciphertexts with context
        let ctx1 = elgamal.wrap_ciphertext(ct1);
        let ctx2 = elgamal.wrap_ciphertext(ct2);

        // Test multiplication: ct1 * ct2
        let ct_product = (&ctx1 * &ctx2).unwrap();
        let decrypted_product = elgamal.decrypt(&ct_product, &keypair.private_key).unwrap();
        assert_eq!((&m1 * &m2) % p, decrypted_product);

        // Test division: ct1 / ct2
        let ct_quotient = (&ctx1 / &ctx2).unwrap();
        let decrypted_quotient = elgamal.decrypt(&ct_quotient, &keypair.private_key).unwrap();
        let expected_quotient = (&m1 * &crate::utils::mod_inverse(&m2, p).unwrap()) % p;
        assert_eq!(expected_quotient, decrypted_quotient);

        // Test scalar multiplication: ct1 * scalar
        let ct_scalar_mul = (&ctx1 * &scalar).unwrap();
        let decrypted_scalar_mul = elgamal
            .decrypt(&ct_scalar_mul, &keypair.private_key)
            .unwrap();
        assert_eq!(crate::utils::mod_exp(&m1, &scalar, p), decrypted_scalar_mul);

        // Test scalar division: ct1 / scalar
        let ct_scalar_div = (&ctx1 / &scalar).unwrap();
        let decrypted_scalar_div = elgamal
            .decrypt(&ct_scalar_div, &keypair.private_key)
            .unwrap();
        let scalar_inv = crate::utils::mod_inverse(&scalar, p).unwrap();
        let expected_scalar_div = crate::utils::mod_exp(&m1, &scalar_inv, p);
        assert_eq!(expected_scalar_div, decrypted_scalar_div);
    }

    #[test]
    fn test_homomorphic_elgamal_wrapper() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);
        let heg = elgamal.into_homomorphic();

        let m1 = 5u32.to_biguint().unwrap();
        let m2 = 3u32.to_biguint().unwrap();
        let scalar = 2u32.to_biguint().unwrap();
        let p = &heg.inner().public_key.p;

        let ct1 = heg.encrypt(&m1).unwrap();
        let ct2 = heg.encrypt(&m2).unwrap();

        // Test addition
        let ct_sum = heg.add(&ct1, &ct2).unwrap();
        let decrypted_sum = heg.decrypt(&ct_sum, &keypair.private_key).unwrap();
        assert_eq!(&m1 + &m2, decrypted_sum);

        // Test subtraction
        let ct_diff = heg.sub(&ct1, &ct2).unwrap();
        let decrypted_diff = heg.decrypt(&ct_diff, &keypair.private_key).unwrap();
        assert_eq!((&m1 + p - &m2) % p, decrypted_diff);

        // Test scalar addition
        let ct_scalar_add = heg.add_scalar(&ct1, &scalar).unwrap();
        let decrypted_scalar_add = heg.decrypt(&ct_scalar_add, &keypair.private_key).unwrap();
        assert_eq!((&m1 + &scalar) % p, decrypted_scalar_add);

        // Test scalar multiplication
        let ct_scalar_mul = heg.mul_scalar(&ct1, &scalar).unwrap();
        let decrypted_scalar_mul = heg.decrypt(&ct_scalar_mul, &keypair.private_key).unwrap();
        assert_eq!((&m1 * &scalar) % p, decrypted_scalar_mul);
    }

    #[test]
    fn test_operator_mode_restrictions() {
        let keypair = KeyPair::generate_for_testing(512).unwrap();
        let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);
        let elgamal_mult =
            ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let m1 = 5u32.to_biguint().unwrap();
        let m2 = 3u32.to_biguint().unwrap();
        let scalar = 2u32.to_biguint().unwrap();

        let ct1_add = elgamal_add.encrypt(&m1).unwrap();
        let ct2_add = elgamal_add.encrypt(&m2).unwrap();
        let ct1_mult = elgamal_mult.encrypt(&m1).unwrap();
        let ct2_mult = elgamal_mult.encrypt(&m2).unwrap();

        // Test that division fails in additive mode
        let heg_add = elgamal_add.into_homomorphic();
        assert!(heg_add.div(&ct1_add, &ct2_add).is_err());

        // Test that subtraction fails in multiplicative mode
        let heg_mult = elgamal_mult.into_homomorphic();
        assert!(heg_mult.sub(&ct1_mult, &ct2_mult).is_err());

        // Test that scalar division fails in additive mode
        assert!(heg_add.div_scalar(&ct1_add, &scalar).is_err());

        // Test that scalar addition fails in multiplicative mode
        assert!(heg_mult.add_scalar(&ct1_mult, &scalar).is_err());
    }
}
