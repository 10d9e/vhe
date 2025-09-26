//! Utility functions for cryptographic operations

use crate::error::{ElGamalError, Result};
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;

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

    // For 512-bit keys, we need more iterations and flexibility
    let max_iterations = if bit_size <= 512 {
        500000 // Much higher for small primes
    } else if bit_size <= 1024 {
        200000
    } else {
        100000
    };

    let mut iterations = 0;

    // Allow a small range of bit sizes for flexibility
    let min_bits = bit_size.saturating_sub(1);
    let max_bits = bit_size + 1;

    loop {
        iterations += 1;
        if iterations > max_iterations {
            return Err(ElGamalError::CryptoError(
                format!("Failed to generate {}-bit safe prime after {} iterations. Consider using generate_for_testing() for tests or a larger key size for production.", bit_size, max_iterations)
            ));
        }

        // Generate a random odd number of approximately the right size
        // For safe primes, q should be about (bit_size - 1) bits
        let mut q = rng.gen_biguint(bit_size - 1);

        // Ensure q is odd
        q |= BigUint::one();

        // Set high bit to ensure minimum size
        if bit_size > 2 {
            q |= BigUint::one() << (bit_size - 2);
        }

        // Quick pre-check: if q is even, skip
        if q.is_even() {
            continue;
        }

        // First check if q is prime (cheaper check)
        if !is_probable_prime(&q, 20) {
            continue;
        }

        // Calculate p = 2q + 1
        let p = &q * 2u32 + 1u32;

        // Check that p has approximately the right bit size (allow some flexibility)
        let p_bits = p.bits();
        if p_bits < min_bits || p_bits > max_bits {
            continue;
        }

        // Check if p is also prime
        if is_probable_prime(&p, 20) {
            return Ok((p, q));
        }
    }
}

/// Generate a safe prime with more lenient bit size requirements (for easier generation)
pub fn generate_safe_prime_lenient(target_bit_size: u64) -> Result<(BigUint, BigUint)> {
    if target_bit_size < 512 {
        return Err(ElGamalError::InvalidKeySize(target_bit_size));
    }

    let mut rng = thread_rng();
    let max_iterations = 1000000; // Very high limit for lenient generation
    let mut iterations = 0;

    // Allow wider range for lenient generation
    let min_bits = target_bit_size.saturating_sub(8);
    let max_bits = target_bit_size + 8;

    loop {
        iterations += 1;
        if iterations > max_iterations {
            return Err(ElGamalError::CryptoError(format!(
                "Failed to generate safe prime near {} bits after {} iterations",
                target_bit_size, max_iterations
            )));
        }

        // Try different bit sizes near the target
        let bit_variation = iterations % 17; // Vary the size slightly
        let attempt_bits = if bit_variation < 8 {
            target_bit_size.saturating_sub(bit_variation / 2)
        } else {
            target_bit_size + (bit_variation - 8) / 2
        };

        let q_bits = attempt_bits.saturating_sub(1);
        let mut q = rng.gen_biguint(q_bits);
        q |= BigUint::one(); // Make odd

        if q_bits > 1 {
            q |= BigUint::one() << (q_bits - 1); // Set high bit
        }

        if is_probable_prime(&q, 15) {
            // Slightly fewer rounds for speed
            let p = &q * 2u32 + 1u32;
            let p_bits = p.bits();

            if p_bits >= min_bits && p_bits <= max_bits && is_probable_prime(&p, 15) {
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

    let two = 2u32.to_biguint().unwrap();
    let three = 3u32.to_biguint().unwrap();

    if n == &two {
        return true;
    }
    if n == &three {
        return true;
    }
    if n.is_even() {
        return false;
    }
    if n < &two {
        return false;
    }

    let mut rng = thread_rng();
    let n_minus_1 = n - BigUint::one();
    let (s, d) = factor_powers_of_two(&n_minus_1);

    'witness: for _ in 0..k {
        // For small n, we need to be careful with the range
        let a = if n == &three {
            two.clone()
        } else {
            let upper = n_minus_1.clone();
            if upper <= two {
                two.clone()
            } else {
                rng.gen_biguint_range(&two, &upper)
            }
        };

        let mut x = mod_exp(&a, &d, n);

        if x == BigUint::one() || x == n_minus_1 {
            continue;
        }

        for _ in 0..s - 1 {
            x = mod_exp(&x, &two, n);
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

    while d.is_even() {
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
        // Known small primes
        assert!(is_probable_prime(&2u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&3u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&5u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&7u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&11u32.to_biguint().unwrap(), 20));
        assert!(is_probable_prime(&13u32.to_biguint().unwrap(), 20));

        // Known composites
        assert!(!is_probable_prime(&4u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&6u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&8u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&9u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&10u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&12u32.to_biguint().unwrap(), 20));
        assert!(!is_probable_prime(&15u32.to_biguint().unwrap(), 20));
    }

    #[test]
    fn test_safe_prime_generation_lenient() {
        // Test that lenient generation works for 512-bit primes
        let result = generate_safe_prime_lenient(512);
        assert!(
            result.is_ok(),
            "Lenient safe prime generation should succeed"
        );

        if let Ok((p, q)) = result {
            // Check that p = 2q + 1
            assert_eq!(p, &q * 2u32 + 1u32);

            // Check that both are prime
            assert!(is_probable_prime(&p, 20));
            assert!(is_probable_prime(&q, 20));

            // Check that bit size is reasonable (within ±8 bits)
            let p_bits = p.bits();
            assert!(
                p_bits >= 504 && p_bits <= 520,
                "Prime should be close to 512 bits, got {}",
                p_bits
            );
        }
    }
}
