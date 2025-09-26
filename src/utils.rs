//! Utility functions for cryptographic operations

use crate::error::{ElGamalError, Result};
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_traits::{One, Zero};
use rand::thread_rng;

/// Check if a BigUint is even
fn is_even(n: &BigUint) -> bool {
    n % 2u32 == BigUint::zero()
}

/// Modular exponentiation: base^exp mod modulus
pub fn mod_exp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

/// Compute modular inverse using extended Euclidean algorithm
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
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

/// Generate a safe prime (p = 2q + 1 where q is also prime)
pub fn generate_safe_prime(bit_size: u64) -> Result<(BigUint, BigUint)> {
    if bit_size < 512 {
        return Err(ElGamalError::InvalidKeySize(bit_size));
    }

    let mut rng = thread_rng();
    let max_iterations = 10000;
    let mut iterations = 0;

    loop {
        iterations += 1;
        if iterations > max_iterations {
            return Err(ElGamalError::CryptoError(
                "Failed to generate safe prime after maximum iterations".to_string(),
            ));
        }

        let q = rng.gen_biguint(bit_size - 1) | BigUint::one();

        if is_probable_prime(&q, 20) {
            let p = &q * 2u32 + 1u32;

            if is_probable_prime(&p, 20) {
                return Ok((p, q));
            }
        }
    }
}

/// Miller-Rabin primality test
pub fn is_probable_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() {
        return false;
    }
    if n == &2u32.to_biguint().unwrap() {
        return true;
    }
    if is_even(n) {
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
pub fn factor_powers_of_two(n: &BigUint) -> (u64, BigUint) {
    let mut s = 0;
    let mut d = n.clone();

    while is_even(&d) {
        d >>= 1;
        s += 1;
    }

    (s, d)
}

/// Find a generator for the multiplicative group modulo p
pub fn find_generator(p: &BigUint, q: &BigUint) -> BigUint {
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

/// Generate a random element in the range [1, n)
pub fn random_in_range(n: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint_range(&BigUint::one(), n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_inverse() {
        let a = 3u32.to_biguint().unwrap();
        let m = 11u32.to_biguint().unwrap();
        let inv = mod_inverse(&a, &m).unwrap();

        assert_eq!((a * inv) % m, BigUint::one());
    }

    #[test]
    fn test_is_probable_prime() {
        // Known primes
        assert!(is_probable_prime(&2u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&3u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&5u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&7u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&11u32.to_biguint().unwrap(), 20));

        // Known composites
        assert!(!is_probable_prime(&4u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&6u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&9u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&15u32.to_biguint().unwrap(), 20));
    }
}
