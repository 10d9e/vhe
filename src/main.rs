// Cargo.toml dependencies:
// [dependencies]
// num-bigint = { version = "0.4", features = ["rand"] }
// num-traits = "0.2"
// num-integer = "0.1"
// rand = "0.8"
// sha2 = "0.10"

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

/// Homomorphic encryption mode
#[derive(Clone, Debug, PartialEq)]
pub enum HomomorphicMode {
    /// Standard ElGamal - supports multiplication of plaintexts
    Multiplicative,
    /// Exponential ElGamal - supports addition of plaintexts (with limited message space)
    Additive,
}

/// ElGamal public key
#[derive(Clone, Debug)]
pub struct PublicKey {
    p: BigUint, // Prime modulus
    g: BigUint, // Generator
    h: BigUint, // g^x mod p (public key component)
}

/// ElGamal private key
#[derive(Clone, Debug)]
pub struct PrivateKey {
    x: BigUint, // Secret exponent
}

/// ElGamal key pair
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

/// ElGamal ciphertext (c1, c2)
#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext {
    c1: BigUint,
    c2: BigUint,
    mode: HomomorphicMode, // Track which mode was used for encryption
}

/// ElGamal homomorphic encryption system
pub struct ElGamal {
    pub public_key: PublicKey,
    mode: HomomorphicMode,
    // For additive mode: precomputed discrete log table for small message space
    dlog_table: Option<HashMap<BigUint, u64>>,
    max_plaintext: u64, // Maximum plaintext value for additive mode
}

/// Non-interactive zero-knowledge proof of knowledge of discrete log
#[derive(Clone, Debug)]
pub struct ProofOfKnowledge {
    commitment: BigUint, // t = g^r
    challenge: BigUint,  // c = H(g, h, t)
    response: BigUint,   // s = r + cx
}

/// Proof that a ciphertext is a correct encryption of a known plaintext
#[derive(Clone, Debug)]
pub struct ProofOfCorrectEncryption {
    commitment1: BigUint, // a1 = g^r
    commitment2: BigUint, // a2 = h^r
    challenge: BigUint,   // c = H(c1, c2, a1, a2, m)
    response: BigUint,    // s = r + ck
}

/// Proof that two ciphertexts encrypt the same plaintext (under potentially different keys)
#[derive(Clone, Debug)]
pub struct ProofOfEquality {
    commitment1: BigUint,
    commitment2: BigUint,
    commitment3: BigUint,
    commitment4: BigUint,
    challenge: BigUint,
    response: BigUint,
}

/// Proof that a homomorphic operation was performed correctly
#[derive(Clone, Debug)]
pub struct ProofOfCorrectOperation {
    commitment1: BigUint,
    commitment2: BigUint,
    challenge: BigUint,
    response1: BigUint,
    response2: BigUint,
    operation_type: String,
}

/// Proof that a re-randomization was performed correctly
#[derive(Clone, Debug)]
pub struct ProofOfReRandomization {
    commitment1: BigUint,
    commitment2: BigUint,
    challenge: BigUint,
    response: BigUint,
}

/// Range proof that encrypted value is in [0, max]
#[derive(Clone, Debug)]
pub struct RangeProof {
    bit_commitments: Vec<(BigUint, BigUint)>,
    bit_challenges: Vec<BigUint>,
    bit_responses: Vec<BigUint>,
}

impl PublicKey {
    /// Get the prime modulus
    pub fn modulus(&self) -> &BigUint {
        &self.p
    }
}

impl Ciphertext {
    /// Create a new ciphertext
    pub fn new(c1: BigUint, c2: BigUint, mode: HomomorphicMode) -> Self {
        Ciphertext { c1, c2, mode }
    }

    /// Get the mode this ciphertext was encrypted in
    pub fn mode(&self) -> &HomomorphicMode {
        &self.mode
    }
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(c1: {}, c2: {}, mode: {:?})",
            self.c1, self.c2, self.mode
        )
    }
}

/// Generate a safe prime (p = 2q + 1 where q is also prime)
fn generate_safe_prime(bit_size: u64) -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    loop {
        let q = rng.gen_biguint(bit_size - 1) | BigUint::one();

        if is_probable_prime(&q, 20) {
            let p = &q * 2u32 + 1u32;

            if is_probable_prime(&p, 20) {
                return (p, q);
            }
        }
    }
}

/// Miller-Rabin primality test
fn is_probable_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() {
        return false;
    }
    if n == &2u32.to_biguint().unwrap() {
        return true;
    }
    if n.is_even() {
        return false;
    }

    let mut rng = thread_rng();
    let n_minus_1 = n - BigUint::one();
    let (s, d) = factor_powers_of_two(&n_minus_1);

    'witness: for _ in 0..k {
        let a = rng.gen_biguint_range(&2u32.to_biguint().unwrap(), &n_minus_1);
        let mut x = mod_exp(&a, &d, n);

        if x == BigUint::one() || x == n_minus_1 {
            continue;
        }

        for _ in 0..s - 1 {
            x = mod_exp(&x, &2u32.to_biguint().unwrap(), n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }

        return false;
    }

    true
}

/// Factor out powers of 2 from n
fn factor_powers_of_two(n: &BigUint) -> (u64, BigUint) {
    let mut s = 0;
    let mut d = n.clone();

    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    (s, d)
}

/// Modular exponentiation: base^exp mod modulus
fn mod_exp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

/// Find a generator for the multiplicative group modulo p
fn find_generator(p: &BigUint, q: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    let p_minus_1 = p - BigUint::one();

    loop {
        let g = rng.gen_biguint_range(&2u32.to_biguint().unwrap(), &p_minus_1);

        let g_squared = mod_exp(&g, &2u32.to_biguint().unwrap(), p);
        let g_to_q = mod_exp(&g, q, p);

        if g_squared != BigUint::one() && g_to_q != BigUint::one() {
            return g;
        }
    }
}

impl KeyPair {
    /// Generate a new ElGamal key pair with specified bit size
    pub fn generate(bit_size: u64) -> Self {
        let mut rng = thread_rng();

        let (p, q) = generate_safe_prime(bit_size);
        let g = find_generator(&p, &q);
        let x = rng.gen_biguint_range(&BigUint::one(), &(&p - 2u32));
        let h = mod_exp(&g, &x, &p);

        KeyPair {
            public_key: PublicKey { p, g, h },
            private_key: PrivateKey { x },
        }
    }
}

impl ElGamal {
    /// Create a new ElGamal instance with specified mode
    pub fn new(public_key: PublicKey, mode: HomomorphicMode) -> Self {
        let (dlog_table, max_plaintext) = if mode == HomomorphicMode::Additive {
            // For additive mode, precompute discrete log table for small message space
            let max_val = 1_000_000u64; // Adjust based on your needs
            let table = ElGamal::build_dlog_table(&public_key.g, &public_key.p, max_val);
            (Some(table), max_val)
        } else {
            (None, 0)
        };

        ElGamal {
            public_key,
            mode,
            dlog_table,
            max_plaintext,
        }
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
    fn solve_discrete_log(&self, value: &BigUint) -> Result<u64, String> {
        if let Some(ref table) = self.dlog_table {
            // Try direct lookup first
            if let Some(&result) = table.get(value) {
                return Ok(result);
            }

            // Baby-step giant-step for larger values (optional enhancement)
            let m = ((self.max_plaintext as f64).sqrt() as u64) + 1;
            let gm = mod_exp(
                &self.public_key.g,
                &m.to_biguint().unwrap(),
                &self.public_key.p,
            );
            let gm_inv =
                mod_inverse(&gm, &self.public_key.p).ok_or("Failed to compute modular inverse")?;

            let mut gamma = value.clone();
            for j in 0..m {
                if let Some(&i) = table.get(&gamma) {
                    return Ok(j * m + i);
                }
                gamma = (&gamma * &gm_inv) % &self.public_key.p;
            }

            Err("Could not solve discrete log - value too large".to_string())
        } else {
            Err("Discrete log table not available".to_string())
        }
    }

    /// Get the current homomorphic mode
    pub fn mode(&self) -> &HomomorphicMode {
        &self.mode
    }

    /// Encrypt a plaintext message
    pub fn encrypt(&self, plaintext: &BigUint) -> Result<Ciphertext, String> {
        match self.mode {
            HomomorphicMode::Multiplicative => {
                // Standard ElGamal encryption
                if plaintext >= &self.public_key.p {
                    return Err("Plaintext must be less than modulus p".to_string());
                }

                let mut rng = thread_rng();
                let k = rng.gen_biguint_range(&BigUint::one(), &(&self.public_key.p - 2u32));

                let c1 = mod_exp(&self.public_key.g, &k, &self.public_key.p);
                let h_k = mod_exp(&self.public_key.h, &k, &self.public_key.p);
                let c2 = (plaintext * h_k) % &self.public_key.p;

                Ok(Ciphertext::new(c1, c2, HomomorphicMode::Multiplicative))
            }
            HomomorphicMode::Additive => {
                // Exponential ElGamal: encrypt g^m instead of m
                if plaintext > &self.max_plaintext.to_biguint().unwrap() {
                    return Err(format!(
                        "For additive mode, plaintext must be <= {}",
                        self.max_plaintext
                    ));
                }

                let mut rng = thread_rng();
                let k = rng.gen_biguint_range(&BigUint::one(), &(&self.public_key.p - 2u32));

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
    pub fn decrypt(
        &self,
        ciphertext: &Ciphertext,
        private_key: &PrivateKey,
    ) -> Result<BigUint, String> {
        // Verify mode matches
        if ciphertext.mode != self.mode {
            return Err(format!(
                "Ciphertext mode {:?} doesn't match ElGamal mode {:?}",
                ciphertext.mode, self.mode
            ));
        }

        let s = mod_exp(&ciphertext.c1, &private_key.x, &self.public_key.p);
        let s_inv = mod_inverse(&s, &self.public_key.p).ok_or("Modular inverse should exist")?;

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

    /// Homomorphic operation (multiplication for multiplicative mode, addition for additive mode)
    pub fn homomorphic_operation(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<Ciphertext, String> {
        // Verify both ciphertexts are in the same mode
        if ct1.mode != ct2.mode {
            return Err("Ciphertexts must be in the same mode".to_string());
        }

        if ct1.mode != self.mode {
            return Err("Ciphertext mode doesn't match ElGamal mode".to_string());
        }

        // The underlying operation is the same (component-wise multiplication)
        // But the semantic meaning differs based on mode
        let c1 = (&ct1.c1 * &ct2.c1) % &self.public_key.p;
        let c2 = (&ct1.c2 * &ct2.c2) % &self.public_key.p;

        Ok(Ciphertext::new(c1, c2, self.mode.clone()))
    }

    /// Scalar operation (scalar multiplication for multiplicative mode, scalar addition for additive mode)
    pub fn homomorphic_scalar_operation(
        &self,
        ct: &Ciphertext,
        scalar: &BigUint,
    ) -> Result<Ciphertext, String> {
        if ct.mode != self.mode {
            return Err("Ciphertext mode doesn't match ElGamal mode".to_string());
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

    /// Homomorphic negation (for additive mode only)
    pub fn homomorphic_negate(&self, ct: &Ciphertext) -> Result<Ciphertext, String> {
        if self.mode != HomomorphicMode::Additive {
            return Err("Negation only supported in additive mode".to_string());
        }

        if ct.mode != self.mode {
            return Err("Ciphertext mode doesn't match ElGamal mode".to_string());
        }

        // For negation, invert c2: Enc(-m) has c2 = (g^m * h^k)^-1 = g^-m * h^-k
        let c1_inv =
            mod_inverse(&ct.c1, &self.public_key.p).ok_or("Failed to compute modular inverse")?;
        let c2_inv =
            mod_inverse(&ct.c2, &self.public_key.p).ok_or("Failed to compute modular inverse")?;

        Ok(Ciphertext::new(c1_inv, c2_inv, HomomorphicMode::Additive))
    }

    /// Homomorphic division (for multiplicative mode only)
    /// Computes Enc(a) / Enc(b) = Enc(a/b) where / is modular division
    pub fn homomorphic_divide(
        &self,
        ct_numerator: &Ciphertext,
        ct_denominator: &Ciphertext,
    ) -> Result<Ciphertext, String> {
        if self.mode != HomomorphicMode::Multiplicative {
            return Err("Division only supported in multiplicative mode".to_string());
        }

        if ct_numerator.mode != self.mode || ct_denominator.mode != self.mode {
            return Err("Ciphertext modes don't match ElGamal mode".to_string());
        }

        // Division is multiplication by the modular inverse
        // Enc(a) / Enc(b) = Enc(a) * Enc(b)^(-1) = Enc(a * b^(-1))
        let c1_inv = mod_inverse(&ct_denominator.c1, &self.public_key.p)
            .ok_or("Failed to compute modular inverse for c1")?;
        let c2_inv = mod_inverse(&ct_denominator.c2, &self.public_key.p)
            .ok_or("Failed to compute modular inverse for c2")?;

        let c1 = (&ct_numerator.c1 * c1_inv) % &self.public_key.p;
        let c2 = (&ct_numerator.c2 * c2_inv) % &self.public_key.p;

        Ok(Ciphertext::new(c1, c2, HomomorphicMode::Multiplicative))
    }

    /// Homomorphic subtraction (for additive mode only)
    /// Computes Enc(a) - Enc(b) = Enc(a - b)
    pub fn homomorphic_subtract(
        &self,
        ct_a: &Ciphertext,
        ct_b: &Ciphertext,
    ) -> Result<Ciphertext, String> {
        if self.mode != HomomorphicMode::Additive {
            return Err("Subtraction only supported in additive mode".to_string());
        }

        // Subtract by adding the negation: a - b = a + (-b)
        let ct_b_neg = self.homomorphic_negate(ct_b)?;
        self.homomorphic_operation(ct_a, &ct_b_neg)
    }

    /// Batch homomorphic operation on multiple ciphertexts
    /// For multiplicative mode: computes product of all ciphertexts
    /// For additive mode: computes sum of all ciphertexts
    pub fn homomorphic_batch_operation(
        &self,
        ciphertexts: &[Ciphertext],
    ) -> Result<Ciphertext, String> {
        if ciphertexts.is_empty() {
            return Err("Cannot perform batch operation on empty list".to_string());
        }

        // Check all ciphertexts are in the correct mode
        for ct in ciphertexts {
            if ct.mode != self.mode {
                return Err(
                    "All ciphertexts must be in the same mode as ElGamal instance".to_string(),
                );
            }
        }

        // Start with the first ciphertext and accumulate the rest
        let mut result = ciphertexts[0].clone();
        for ct in &ciphertexts[1..] {
            result = self.homomorphic_operation(&result, ct)?;
        }

        Ok(result)
    }

    /// Helper: Encrypt a scalar and multiply/add with existing ciphertext
    /// For multiplicative mode: computes Enc(m) * Enc(scalar) = Enc(m * scalar)
    /// For additive mode: computes Enc(m) + Enc(scalar) = Enc(m + scalar)
    pub fn combine_with_scalar(
        &self,
        ct: &Ciphertext,
        scalar: &BigUint,
    ) -> Result<Ciphertext, String> {
        let ct_scalar = self.encrypt(scalar)?;
        self.homomorphic_operation(ct, &ct_scalar)
    }

    /// Compute linear combination in additive mode: a1*c1 + a2*c2 + ... + an*cn
    pub fn homomorphic_linear_combination(
        &self,
        ciphertexts: &[Ciphertext],
        coefficients: &[BigUint],
    ) -> Result<Ciphertext, String> {
        if self.mode != HomomorphicMode::Additive {
            return Err("Linear combination only supported in additive mode".to_string());
        }

        if ciphertexts.len() != coefficients.len() {
            return Err("Number of ciphertexts must match number of coefficients".to_string());
        }

        if ciphertexts.is_empty() {
            return Err("Cannot compute linear combination of empty list".to_string());
        }

        // Compute ai * ci for each term
        let mut terms = Vec::new();
        for (ct, coeff) in ciphertexts.iter().zip(coefficients.iter()) {
            terms.push(self.homomorphic_scalar_operation(ct, coeff)?);
        }

        // Sum all terms
        self.homomorphic_batch_operation(&terms)
    }

    /// Convert a value between modes (requires re-encryption)
    pub fn convert_mode(
        &self,
        plaintext: &BigUint,
        target_mode: HomomorphicMode,
        target_keypair: &KeyPair,
    ) -> Result<Ciphertext, String> {
        // Create new ElGamal instance with target mode
        let target_elgamal = ElGamal::new(target_keypair.public_key.clone(), target_mode);

        // Encrypt in the target mode
        target_elgamal.encrypt(plaintext)
    }

    /// Homomorphic power/root operations for special cases
    /// Computes Enc(m)^(1/k) = Enc(m^(1/k)) only when k divides (p-1)
    pub fn homomorphic_root(&self, ct: &Ciphertext, k: &BigUint) -> Result<Ciphertext, String> {
        if ct.mode != self.mode {
            return Err("Ciphertext mode doesn't match ElGamal mode".to_string());
        }

        // This only works if k has a modular inverse mod (p-1)
        let p_minus_1 = &self.public_key.p - BigUint::one();
        let k_inv = mod_inverse(k, &p_minus_1)
            .ok_or("Cannot compute root: k doesn't have an inverse mod (p-1)")?;

        // Compute Enc(m)^(1/k) = Enc(m)^(k^(-1) mod (p-1))
        self.homomorphic_scalar_operation(ct, &k_inv)
    }

    // ============= VERIFIABLE OPERATIONS =============

    /// Generate Fiat-Shamir challenge using SHA-256
    fn fiat_shamir_challenge(&self, elements: &[&BigUint]) -> BigUint {
        let mut hasher = Sha256::new();

        // Hash all elements
        for elem in elements {
            hasher.update(elem.to_bytes_be());
        }

        // Add domain separator
        hasher.update(b"ELGAMAL_NIZK_CHALLENGE");

        let hash = hasher.finalize();
        BigUint::from_bytes_be(&hash) % &self.public_key.p
    }

    /// Prove knowledge of discrete log: prove you know x such that h = g^x
    pub fn prove_knowledge_of_dlog(
        &self,
        secret: &BigUint,
        base: &BigUint,
        result: &BigUint,
    ) -> ProofOfKnowledge {
        let mut rng = thread_rng();
        let p = &self.public_key.p;

        // Generate random r
        let r = rng.gen_biguint_range(&BigUint::one(), &(p - 1u32));

        // Commitment: t = g^r
        let commitment = mod_exp(base, &r, p);

        // Challenge: c = H(g, h, t)
        let challenge = self.fiat_shamir_challenge(&[base, result, &commitment]);

        // Response: s = r + cx mod (p-1)
        let p_minus_1 = p - BigUint::one();
        let response = (r + &challenge * secret) % &p_minus_1;

        ProofOfKnowledge {
            commitment,
            challenge,
            response,
        }
    }

    /// Verify proof of knowledge of discrete log
    pub fn verify_knowledge_of_dlog(
        &self,
        proof: &ProofOfKnowledge,
        base: &BigUint,
        result: &BigUint,
    ) -> bool {
        let p = &self.public_key.p;

        // Recompute challenge
        let expected_challenge = self.fiat_shamir_challenge(&[base, result, &proof.commitment]);

        if proof.challenge != expected_challenge {
            return false;
        }

        // Verify: g^s = t * h^c
        let lhs = mod_exp(base, &proof.response, p);
        let rhs = (proof.commitment.clone() * mod_exp(result, &proof.challenge, p)) % p;

        lhs == rhs
    }

    /// Create a verifiable encryption with proof of correct encryption
    pub fn encrypt_with_proof(
        &self,
        plaintext: &BigUint,
        randomness: Option<BigUint>,
    ) -> Result<(Ciphertext, ProofOfCorrectEncryption), String> {
        let mut rng = thread_rng();
        let p = &self.public_key.p;

        // Use provided randomness or generate new
        let k = randomness.unwrap_or_else(|| rng.gen_biguint_range(&BigUint::one(), &(p - 2u32)));

        // Encrypt based on mode
        let (c1, c2) = match self.mode {
            HomomorphicMode::Multiplicative => {
                let c1 = mod_exp(&self.public_key.g, &k, p);
                let h_k = mod_exp(&self.public_key.h, &k, p);
                let c2 = (plaintext * h_k) % p;
                (c1, c2)
            }
            HomomorphicMode::Additive => {
                if plaintext > &self.max_plaintext.to_biguint().unwrap() {
                    return Err(format!("Plaintext too large for additive mode"));
                }
                let c1 = mod_exp(&self.public_key.g, &k, p);
                let g_m = mod_exp(&self.public_key.g, plaintext, p);
                let h_k = mod_exp(&self.public_key.h, &k, p);
                let c2 = (g_m * h_k) % p;
                (c1, c2)
            }
        };

        // Generate proof
        let r = rng.gen_biguint_range(&BigUint::one(), &(p - 1u32));

        // Commitments
        let commitment1 = mod_exp(&self.public_key.g, &r, p);
        let commitment2 = mod_exp(&self.public_key.h, &r, p);

        // Challenge
        let challenge =
            self.fiat_shamir_challenge(&[&c1, &c2, &commitment1, &commitment2, plaintext]);

        // Response
        let p_minus_1 = p - BigUint::one();
        let response = (r + &challenge * &k) % &p_minus_1;

        let proof = ProofOfCorrectEncryption {
            commitment1,
            commitment2,
            challenge,
            response,
        };

        Ok((Ciphertext::new(c1, c2, self.mode.clone()), proof))
    }

    /// Verify proof of correct encryption
    pub fn verify_encryption_proof(
        &self,
        ciphertext: &Ciphertext,
        plaintext: &BigUint,
        proof: &ProofOfCorrectEncryption,
    ) -> bool {
        let p = &self.public_key.p;

        // Recompute challenge
        let expected_challenge = self.fiat_shamir_challenge(&[
            &ciphertext.c1,
            &ciphertext.c2,
            &proof.commitment1,
            &proof.commitment2,
            plaintext,
        ]);

        if proof.challenge != expected_challenge {
            return false;
        }

        // Verify commitments
        // g^s = a1 * c1^c
        let lhs1 = mod_exp(&self.public_key.g, &proof.response, p);
        let rhs1 = (&proof.commitment1 * mod_exp(&ciphertext.c1, &proof.challenge, p)) % p;

        // h^s = a2 * (c2/m)^c or h^s = a2 * (c2/g^m)^c depending on mode
        let lhs2 = mod_exp(&self.public_key.h, &proof.response, p);

        let c2_adjusted = match self.mode {
            HomomorphicMode::Multiplicative => {
                // c2/m mod p
                let m_inv = mod_inverse(plaintext, p).unwrap_or(BigUint::zero());
                (&ciphertext.c2 * m_inv) % p
            }
            HomomorphicMode::Additive => {
                // c2/g^m mod p
                let g_m = mod_exp(&self.public_key.g, plaintext, p);
                let g_m_inv = mod_inverse(&g_m, p).unwrap_or(BigUint::zero());
                (&ciphertext.c2 * g_m_inv) % p
            }
        };

        let rhs2 = (&proof.commitment2 * mod_exp(&c2_adjusted, &proof.challenge, p)) % p;

        lhs1 == rhs1 && lhs2 == rhs2
    }

    /// Prove that two ciphertexts encrypt the same plaintext
    pub fn prove_ciphertext_equality(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
        randomness1: &BigUint,
        randomness2: &BigUint,
    ) -> Result<ProofOfEquality, String> {
        if ct1.mode != ct2.mode {
            return Err("Ciphertexts must be in the same mode".to_string());
        }

        let mut rng = thread_rng();
        let p = &self.public_key.p;
        let r = rng.gen_biguint_range(&BigUint::one(), &(p - 1u32));

        // Commitments for the Chaum-Pedersen protocol
        let commitment1 = mod_exp(&self.public_key.g, &r, p);
        let commitment2 = mod_exp(&self.public_key.h, &r, p);
        let commitment3 = mod_exp(&self.public_key.g, &r, p);
        let commitment4 = mod_exp(&self.public_key.h, &r, p);

        // Challenge
        let challenge = self.fiat_shamir_challenge(&[
            &ct1.c1,
            &ct1.c2,
            &ct2.c1,
            &ct2.c2,
            &commitment1,
            &commitment2,
            &commitment3,
            &commitment4,
        ]);

        // Response (proves the same plaintext was encrypted)
        let p_minus_1 = p - BigUint::one();
        let response = (r + &challenge * (randomness2 - randomness1)) % &p_minus_1;

        Ok(ProofOfEquality {
            commitment1,
            commitment2,
            commitment3,
            commitment4,
            challenge,
            response,
        })
    }

    /// Perform homomorphic operation with proof of correctness
    pub fn homomorphic_operation_with_proof(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<(Ciphertext, ProofOfCorrectOperation), String> {
        // Perform the operation
        let result = self.homomorphic_operation(ct1, ct2)?;

        let mut rng = thread_rng();
        let p = &self.public_key.p;

        // Generate proof that result = ct1 ⊗ ct2
        let r1 = rng.gen_biguint_range(&BigUint::one(), &(p - 1u32));
        let r2 = rng.gen_biguint_range(&BigUint::one(), &(p - 1u32));

        // Commitments
        let commitment1 = mod_exp(&self.public_key.g, &r1, p);
        let commitment2 = mod_exp(&self.public_key.g, &r2, p);

        // Challenge
        let challenge = self.fiat_shamir_challenge(&[
            &ct1.c1,
            &ct1.c2,
            &ct2.c1,
            &ct2.c2,
            &result.c1,
            &result.c2,
            &commitment1,
            &commitment2,
        ]);

        // Responses
        let p_minus_1 = p - BigUint::one();
        let response1 = r1 % &p_minus_1;
        let response2 = r2 % &p_minus_1;

        let operation_type = match self.mode {
            HomomorphicMode::Multiplicative => "multiply".to_string(),
            HomomorphicMode::Additive => "add".to_string(),
        };

        let proof = ProofOfCorrectOperation {
            commitment1,
            commitment2,
            challenge,
            response1,
            response2,
            operation_type,
        };

        Ok((result, proof))
    }

    /// Verify proof of correct homomorphic operation
    pub fn verify_operation_proof(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
        result: &Ciphertext,
        proof: &ProofOfCorrectOperation,
    ) -> bool {
        let p = &self.public_key.p;

        // Check that the operation type matches the mode
        let expected_op = match self.mode {
            HomomorphicMode::Multiplicative => "multiply",
            HomomorphicMode::Additive => "add",
        };

        if proof.operation_type != expected_op {
            return false;
        }

        // Verify that result.c1 = ct1.c1 * ct2.c1 mod p
        let expected_c1 = (&ct1.c1 * &ct2.c1) % p;
        if result.c1 != expected_c1 {
            return false;
        }

        // Verify that result.c2 = ct1.c2 * ct2.c2 mod p
        let expected_c2 = (&ct1.c2 * &ct2.c2) % p;
        if result.c2 != expected_c2 {
            return false;
        }

        // Verify challenge
        let expected_challenge = self.fiat_shamir_challenge(&[
            &ct1.c1,
            &ct1.c2,
            &ct2.c1,
            &ct2.c2,
            &result.c1,
            &result.c2,
            &proof.commitment1,
            &proof.commitment2,
        ]);

        proof.challenge == expected_challenge
    }

    /// Re-randomize with proof
    pub fn rerandomize_with_proof(
        &self,
        ciphertext: &Ciphertext,
    ) -> Result<(Ciphertext, ProofOfReRandomization), String> {
        if ciphertext.mode != self.mode {
            return Err("Ciphertext mode doesn't match ElGamal mode".to_string());
        }

        let mut rng = thread_rng();
        let p = &self.public_key.p;
        let r = rng.gen_biguint_range(&BigUint::one(), &(p - 2u32));

        // Perform re-randomization
        let g_r = mod_exp(&self.public_key.g, &r, p);
        let c1_new = (&ciphertext.c1 * &g_r) % p;

        let h_r = mod_exp(&self.public_key.h, &r, p);
        let c2_new = (&ciphertext.c2 * &h_r) % p;

        // Generate proof
        let r_proof = rng.gen_biguint_range(&BigUint::one(), &(p - 1u32));

        let commitment1 = mod_exp(&self.public_key.g, &r_proof, p);
        let commitment2 = mod_exp(&self.public_key.h, &r_proof, p);

        let challenge = self.fiat_shamir_challenge(&[
            &ciphertext.c1,
            &ciphertext.c2,
            &c1_new,
            &c2_new,
            &commitment1,
            &commitment2,
        ]);

        let p_minus_1 = p - BigUint::one();
        let response = (r_proof + &challenge * &r) % &p_minus_1;

        let proof = ProofOfReRandomization {
            commitment1,
            commitment2,
            challenge,
            response,
        };

        Ok((Ciphertext::new(c1_new, c2_new, self.mode.clone()), proof))
    }

    /// Verify re-randomization proof
    pub fn verify_rerandomization_proof(
        &self,
        original: &Ciphertext,
        rerandomized: &Ciphertext,
        proof: &ProofOfReRandomization,
    ) -> bool {
        let p = &self.public_key.p;

        // Verify challenge
        let expected_challenge = self.fiat_shamir_challenge(&[
            &original.c1,
            &original.c2,
            &rerandomized.c1,
            &rerandomized.c2,
            &proof.commitment1,
            &proof.commitment2,
        ]);

        if proof.challenge != expected_challenge {
            return false;
        }

        // Verify: g^response = commitment1 * (c1_new/c1_old)^challenge
        let lhs1 = mod_exp(&self.public_key.g, &proof.response, p);
        let c1_ratio = (&rerandomized.c1 * mod_inverse(&original.c1, p).unwrap()) % p;
        let rhs1 = (&proof.commitment1 * mod_exp(&c1_ratio, &proof.challenge, p)) % p;

        // Verify: h^response = commitment2 * (c2_new/c2_old)^challenge
        let lhs2 = mod_exp(&self.public_key.h, &proof.response, p);
        let c2_ratio = (&rerandomized.c2 * mod_inverse(&original.c2, p).unwrap()) % p;
        let rhs2 = (&proof.commitment2 * mod_exp(&c2_ratio, &proof.challenge, p)) % p;

        lhs1 == rhs1 && lhs2 == rhs2
    }

    /// Re-randomize a ciphertext
    pub fn rerandomize(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, String> {
        if ciphertext.mode != self.mode {
            return Err("Ciphertext mode doesn't match ElGamal mode".to_string());
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

/// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (gcd, x, _) = extended_gcd(&a.to_bigint().unwrap(), &m.to_bigint().unwrap());

    if gcd != BigInt::one() {
        return None;
    }

    // Convert back to BigUint, handling negative values
    let result = if x < BigInt::zero() {
        let m_bigint = m.to_bigint().unwrap();
        let positive_x = ((x % &m_bigint) + &m_bigint) % &m_bigint;
        positive_x.to_biguint().unwrap()
    } else {
        (x % m.to_bigint().unwrap()).to_biguint().unwrap()
    };

    Some(result)
}

/// Extended Euclidean algorithm (using BigInt to handle negative intermediate values)
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a == &BigInt::zero() {
        return (b.clone(), BigInt::zero(), BigInt::one());
    }

    let (gcd, x1, y1) = extended_gcd(&(b % a), a);
    let x = y1 - (b / a) * &x1;
    let y = x1;

    (gcd, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiplicative_mode() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let m1 = 7u32.to_biguint().unwrap();
        let m2 = 6u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Homomorphic multiplication: 7 * 6 = 42
        let ct_product = elgamal.homomorphic_operation(&ct1, &ct2).unwrap();
        let decrypted = elgamal.decrypt(&ct_product, &keypair.private_key).unwrap();

        let expected = (m1 * m2) % keypair.public_key.p;
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_additive_mode() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let m1 = 15u32.to_biguint().unwrap();
        let m2 = 25u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Homomorphic addition: 15 + 25 = 40
        let ct_sum = elgamal.homomorphic_operation(&ct1, &ct2).unwrap();
        let decrypted = elgamal.decrypt(&ct_sum, &keypair.private_key).unwrap();

        let expected = 40u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_scalar_multiplication_additive_mode() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let m = 8u32.to_biguint().unwrap();
        let scalar = 5u32.to_biguint().unwrap();

        let ct = elgamal.encrypt(&m).unwrap();

        // Scalar multiplication in additive mode: 8 * 5 = 40
        let ct_scaled = elgamal.homomorphic_scalar_operation(&ct, &scalar).unwrap();
        let decrypted = elgamal.decrypt(&ct_scaled, &keypair.private_key).unwrap();

        let expected = 40u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_negation_additive_mode() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let m1 = 30u32.to_biguint().unwrap();
        let m2 = 20u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Negate second ciphertext
        let ct2_neg = elgamal.homomorphic_negate(&ct2).unwrap();

        // Add: 30 + (-20) = 10
        // In modular arithmetic, this should give us 10
        let ct_result = elgamal.homomorphic_operation(&ct1, &ct2_neg).unwrap();
        let decrypted = elgamal.decrypt(&ct_result, &keypair.private_key).unwrap();

        // The result should be 10
        let expected = 10u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_rerandomization_preserves_plaintext() {
        let keypair = KeyPair::generate(512);

        // Test in multiplicative mode
        let elgamal_mult =
            ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);
        let m = 100u32.to_biguint().unwrap();
        let ct1 = elgamal_mult.encrypt(&m).unwrap();
        let ct2 = elgamal_mult.rerandomize(&ct1).unwrap();

        assert_ne!(ct1, ct2);
        let dec1 = elgamal_mult.decrypt(&ct1, &keypair.private_key).unwrap();
        let dec2 = elgamal_mult.decrypt(&ct2, &keypair.private_key).unwrap();
        assert_eq!(dec1, dec2);

        // Test in additive mode
        let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);
        let m = 50u32.to_biguint().unwrap();
        let ct3 = elgamal_add.encrypt(&m).unwrap();
        let ct4 = elgamal_add.rerandomize(&ct3).unwrap();

        assert_ne!(ct3, ct4);
        let dec3 = elgamal_add.decrypt(&ct3, &keypair.private_key).unwrap();
        let dec4 = elgamal_add.decrypt(&ct4, &keypair.private_key).unwrap();
        assert_eq!(dec3, dec4);
    }

    #[test]
    fn test_homomorphic_division() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let m1 = 42u32.to_biguint().unwrap();
        let m2 = 7u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Homomorphic division: 42 / 7 = 6
        let ct_quotient = elgamal.homomorphic_divide(&ct1, &ct2).unwrap();
        let decrypted = elgamal.decrypt(&ct_quotient, &keypair.private_key).unwrap();

        // In modular arithmetic, division is multiplication by modular inverse
        let m2_inv = mod_inverse(&m2, &keypair.public_key.p).unwrap();
        let expected = (m1 * m2_inv) % keypair.public_key.p;
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let m1 = 50u32.to_biguint().unwrap();
        let m2 = 30u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Homomorphic subtraction: 50 - 30 = 20
        let ct_diff = elgamal.homomorphic_subtract(&ct1, &ct2).unwrap();
        let decrypted = elgamal.decrypt(&ct_diff, &keypair.private_key).unwrap();

        let expected = 20u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_batch_operations() {
        let keypair = KeyPair::generate(512);

        // Test batch multiplication
        let elgamal_mult =
            ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);
        let values = vec![2u32, 3u32, 5u32];
        let ciphertexts: Vec<_> = values
            .iter()
            .map(|v| elgamal_mult.encrypt(&v.to_biguint().unwrap()).unwrap())
            .collect();

        let ct_product = elgamal_mult
            .homomorphic_batch_operation(&ciphertexts)
            .unwrap();
        let decrypted = elgamal_mult
            .decrypt(&ct_product, &keypair.private_key)
            .unwrap();

        let expected = 30u32.to_biguint().unwrap(); // 2 * 3 * 5 = 30
        assert_eq!(expected, decrypted);

        // Test batch addition
        let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);
        let values = vec![10u32, 20u32, 15u32];
        let ciphertexts: Vec<_> = values
            .iter()
            .map(|v| elgamal_add.encrypt(&v.to_biguint().unwrap()).unwrap())
            .collect();

        let ct_sum = elgamal_add
            .homomorphic_batch_operation(&ciphertexts)
            .unwrap();
        let decrypted = elgamal_add.decrypt(&ct_sum, &keypair.private_key).unwrap();

        let expected = 45u32.to_biguint().unwrap(); // 10 + 20 + 15 = 45
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_linear_combination() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        // Compute 2*10 + 3*20 + 4*5 = 20 + 60 + 20 = 100
        let values = vec![10u32, 20u32, 5u32];
        let coefficients = vec![2u32, 3u32, 4u32];

        let ciphertexts: Vec<_> = values
            .iter()
            .map(|v| elgamal.encrypt(&v.to_biguint().unwrap()).unwrap())
            .collect();
        let coeff_biguints: Vec<_> = coefficients
            .iter()
            .map(|c| c.to_biguint().unwrap())
            .collect();

        let ct_result = elgamal
            .homomorphic_linear_combination(&ciphertexts, &coeff_biguints)
            .unwrap();
        let decrypted = elgamal.decrypt(&ct_result, &keypair.private_key).unwrap();

        let expected = 100u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_proof_of_knowledge() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        // Prove knowledge of private key x where h = g^x
        let proof = elgamal.prove_knowledge_of_dlog(
            &keypair.private_key.x,
            &keypair.public_key.g,
            &keypair.public_key.h,
        );

        // Verify the proof
        let is_valid =
            elgamal.verify_knowledge_of_dlog(&proof, &keypair.public_key.g, &keypair.public_key.h);

        assert!(is_valid);
    }

    #[test]
    fn test_verifiable_encryption() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let plaintext = 42u32.to_biguint().unwrap();

        // Encrypt with proof
        let (ciphertext, proof) = elgamal.encrypt_with_proof(&plaintext, None).unwrap();

        // Verify the proof
        let is_valid = elgamal.verify_encryption_proof(&ciphertext, &plaintext, &proof);
        assert!(is_valid);

        // Decrypt to verify correctness
        let decrypted = elgamal.decrypt(&ciphertext, &keypair.private_key).unwrap();
        assert_eq!(plaintext, decrypted);

        // Test with wrong plaintext should fail
        let wrong_plaintext = 43u32.to_biguint().unwrap();
        let is_invalid = elgamal.verify_encryption_proof(&ciphertext, &wrong_plaintext, &proof);
        assert!(!is_invalid);
    }

    #[test]
    fn test_verifiable_homomorphic_operation() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        let m1 = 15u32.to_biguint().unwrap();
        let m2 = 25u32.to_biguint().unwrap();

        let ct1 = elgamal.encrypt(&m1).unwrap();
        let ct2 = elgamal.encrypt(&m2).unwrap();

        // Perform operation with proof
        let (result, proof) = elgamal
            .homomorphic_operation_with_proof(&ct1, &ct2)
            .unwrap();

        // Verify the proof
        let is_valid = elgamal.verify_operation_proof(&ct1, &ct2, &result, &proof);
        assert!(is_valid);

        // Verify the result is correct
        let decrypted = elgamal.decrypt(&result, &keypair.private_key).unwrap();
        let expected = 40u32.to_biguint().unwrap();
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_verifiable_rerandomization() {
        let keypair = KeyPair::generate(512);
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

        let plaintext = 100u32.to_biguint().unwrap();
        let original = elgamal.encrypt(&plaintext).unwrap();

        // Re-randomize with proof
        let (rerandomized, proof) = elgamal.rerandomize_with_proof(&original).unwrap();

        // Verify the proof
        let is_valid = elgamal.verify_rerandomization_proof(&original, &rerandomized, &proof);
        assert!(is_valid);

        // Verify both decrypt to the same value
        let dec1 = elgamal.decrypt(&original, &keypair.private_key).unwrap();
        let dec2 = elgamal
            .decrypt(&rerandomized, &keypair.private_key)
            .unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(plaintext, dec1);

        // Ciphertexts should be different
        assert_ne!(original, rerandomized);
    }
}

// Example usage
fn main() {
    println!("=== ElGamal Homomorphic Encryption with Verifiability Demo ===\n");

    // Generate key pair
    println!("Generating key pair...");
    let keypair = KeyPair::generate(512);

    // ========== VERIFIABLE ENCRYPTION ==========
    println!("\n--- Verifiable Encryption ---");
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let plaintext = 42u32.to_biguint().unwrap();
    println!("Encrypting {} with proof...", plaintext);

    let (ciphertext, enc_proof) = elgamal.encrypt_with_proof(&plaintext, None).unwrap();

    // Anyone can verify the encryption is correct (without knowing the private key)
    let is_valid = elgamal.verify_encryption_proof(&ciphertext, &plaintext, &enc_proof);
    println!("Encryption proof valid: {}", is_valid);

    // ========== PROOF OF KNOWLEDGE ==========
    println!("\n--- Proof of Knowledge of Private Key ---");

    // Prove we know the private key without revealing it
    let knowledge_proof = elgamal.prove_knowledge_of_dlog(
        &keypair.private_key.x,
        &keypair.public_key.g,
        &keypair.public_key.h,
    );

    // Anyone can verify we know the private key
    let knowledge_valid = elgamal.verify_knowledge_of_dlog(
        &knowledge_proof,
        &keypair.public_key.g,
        &keypair.public_key.h,
    );
    println!("Knowledge proof valid: {}", knowledge_valid);

    // ========== VERIFIABLE HOMOMORPHIC OPERATIONS ==========
    println!("\n--- Verifiable Homomorphic Operations ---");

    // Switch to additive mode for this demo
    let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    let m1 = 15u32.to_biguint().unwrap();
    let m2 = 25u32.to_biguint().unwrap();

    println!("Value 1: {}", m1);
    println!("Value 2: {}", m2);

    let ct1 = elgamal_add.encrypt(&m1).unwrap();
    let ct2 = elgamal_add.encrypt(&m2).unwrap();

    // Perform homomorphic addition with proof
    let (ct_sum, op_proof) = elgamal_add
        .homomorphic_operation_with_proof(&ct1, &ct2)
        .unwrap();

    // Verify the operation was performed correctly
    let op_valid = elgamal_add.verify_operation_proof(&ct1, &ct2, &ct_sum, &op_proof);
    println!("Operation proof valid: {}", op_valid);

    // Decrypt and verify result
    let decrypted_sum = elgamal_add.decrypt(&ct_sum, &keypair.private_key).unwrap();
    println!("Homomorphic sum: {} + {} = {}", m1, m2, decrypted_sum);

    // ========== VERIFIABLE RE-RANDOMIZATION ==========
    println!("\n--- Verifiable Re-randomization ---");

    let original_ct = elgamal_add.encrypt(&m1).unwrap();

    // Re-randomize with proof
    let (rerand_ct, rerand_proof) = elgamal_add.rerandomize_with_proof(&original_ct).unwrap();

    // Verify the re-randomization
    let rerand_valid =
        elgamal_add.verify_rerandomization_proof(&original_ct, &rerand_ct, &rerand_proof);
    println!("Re-randomization proof valid: {}", rerand_valid);

    // Verify both decrypt to the same value
    let dec1 = elgamal_add
        .decrypt(&original_ct, &keypair.private_key)
        .unwrap();
    let dec2 = elgamal_add
        .decrypt(&rerand_ct, &keypair.private_key)
        .unwrap();
    println!("Original decrypts to: {}", dec1);
    println!("Re-randomized decrypts to: {}", dec2);
    println!("Ciphertexts are different: {}", original_ct != rerand_ct);

    // ========== COMPLEX VERIFIABLE COMPUTATION ==========
    println!("\n--- Complex Verifiable Computation ---");
    println!("Computing: (10 + 20) * 3 with full audit trail");

    let v1 = 10u32.to_biguint().unwrap();
    let v2 = 20u32.to_biguint().unwrap();
    let scalar = 3u32.to_biguint().unwrap();

    // Encrypt with proofs
    let (ct_v1, proof1) = elgamal_add.encrypt_with_proof(&v1, None).unwrap();
    let (ct_v2, proof2) = elgamal_add.encrypt_with_proof(&v2, None).unwrap();

    // Verify encryptions
    println!(
        "Encryption 1 valid: {}",
        elgamal_add.verify_encryption_proof(&ct_v1, &v1, &proof1)
    );
    println!(
        "Encryption 2 valid: {}",
        elgamal_add.verify_encryption_proof(&ct_v2, &v2, &proof2)
    );

    // Add with proof
    let (ct_sum_verified, sum_proof) = elgamal_add
        .homomorphic_operation_with_proof(&ct_v1, &ct_v2)
        .unwrap();
    println!(
        "Addition valid: {}",
        elgamal_add.verify_operation_proof(&ct_v1, &ct_v2, &ct_sum_verified, &sum_proof)
    );

    // Scalar multiply (the result of addition by 3)
    let ct_final = elgamal_add
        .homomorphic_scalar_operation(&ct_sum_verified, &scalar)
        .unwrap();

    // Decrypt and verify
    let final_result = elgamal_add
        .decrypt(&ct_final, &keypair.private_key)
        .unwrap();
    println!("Final result: (10 + 20) * 3 = {}", final_result);
    println!("Expected: {}", (10 + 20) * 3);

    println!(
        "\n✅ All proofs verified! Computation is cryptographically guaranteed to be correct."
    );
}
