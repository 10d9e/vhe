//! Integration tests for the ElGamal library

use num_bigint::ToBigUint;
use vhe::{
    Ciphertext, ElGamal, HomomorphicMode, HomomorphicOperations, KeyPair, VerifiableOperations,
};

#[test]
fn test_end_to_end_multiplicative_workflow() {
    // Generate keys using faster method for testing
    let keypair = KeyPair::generate_for_testing(512).expect("Failed to generate keys");
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    // Encrypt multiple values
    let values = vec![2u32, 3u32, 5u32, 7u32];
    let ciphertexts: Vec<Ciphertext> = values
        .iter()
        .map(|v| elgamal.encrypt(&v.to_biguint().unwrap()).unwrap())
        .collect();

    // Perform batch multiplication
    let product_ct = elgamal.homomorphic_batch_operation(&ciphertexts).unwrap();

    // Decrypt result
    let decrypted = elgamal.decrypt(&product_ct, &keypair.private_key).unwrap();

    // Verify result
    let expected = 2u32 * 3 * 5 * 7;
    assert_eq!(decrypted, expected.to_biguint().unwrap());
}

#[test]
fn test_end_to_end_additive_workflow() {
    // Generate keys using faster method for testing
    let keypair = KeyPair::generate_for_testing(512).expect("Failed to generate keys");
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Test addition
    let a = 100u32.to_biguint().unwrap();
    let b = 200u32.to_biguint().unwrap();

    let ct_a = elgamal.encrypt(&a).unwrap();
    let ct_b = elgamal.encrypt(&b).unwrap();

    let ct_sum = elgamal.homomorphic_operation(&ct_a, &ct_b).unwrap();
    let sum = elgamal.decrypt(&ct_sum, &keypair.private_key).unwrap();

    assert_eq!(sum, 300u32.to_biguint().unwrap());

    // Test subtraction
    let ct_diff = elgamal.homomorphic_subtract(&ct_b, &ct_a).unwrap();
    let diff = elgamal.decrypt(&ct_diff, &keypair.private_key).unwrap();

    assert_eq!(diff, 100u32.to_biguint().unwrap());

    // Test scalar multiplication
    let scalar = 5u32.to_biguint().unwrap();
    let ct_scaled = elgamal
        .homomorphic_scalar_operation(&ct_a, &scalar)
        .unwrap();
    let scaled = elgamal.decrypt(&ct_scaled, &keypair.private_key).unwrap();

    assert_eq!(scaled, 500u32.to_biguint().unwrap());
}

#[test]
fn test_linear_combination() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Create encrypted values
    let values = vec![10u32, 20u32, 30u32];
    let coefficients = vec![2u32, 3u32, 4u32];

    let ciphertexts: Vec<_> = values
        .iter()
        .map(|v| elgamal.encrypt(&v.to_biguint().unwrap()).unwrap())
        .collect();

    let coeff_biguints: Vec<_> = coefficients
        .iter()
        .map(|c| c.to_biguint().unwrap())
        .collect();

    // Compute linear combination: 2*10 + 3*20 + 4*30 = 200
    let result_ct = elgamal
        .homomorphic_linear_combination(&ciphertexts, &coeff_biguints)
        .unwrap();
    let result = elgamal.decrypt(&result_ct, &keypair.private_key).unwrap();

    assert_eq!(result, 200u32.to_biguint().unwrap());
}

#[test]
fn test_verifiable_operations_workflow() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Encrypt with proof
    let value = 42u32.to_biguint().unwrap();
    let (ct, proof) = elgamal.encrypt_with_proof(&value, None).unwrap();

    // Verify proof
    assert!(elgamal.verify_encryption_proof(&ct, &value, &proof));

    // Verify with wrong value should fail
    let wrong_value = 43u32.to_biguint().unwrap();
    assert!(!elgamal.verify_encryption_proof(&ct, &wrong_value, &proof));

    // Perform operation with proof
    let value2 = 58u32.to_biguint().unwrap();
    let ct2 = elgamal.encrypt(&value2).unwrap();

    let (result_ct, op_proof) = elgamal.homomorphic_operation_with_proof(&ct, &ct2).unwrap();

    // Verify operation proof
    assert!(elgamal.verify_operation_proof(&ct, &ct2, &result_ct, &op_proof));

    // Verify result
    let result = elgamal.decrypt(&result_ct, &keypair.private_key).unwrap();
    assert_eq!(result, 100u32.to_biguint().unwrap());
}

#[test]
fn test_rerandomization_preserves_plaintext() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();

    for mode in [HomomorphicMode::Multiplicative, HomomorphicMode::Additive] {
        let elgamal = ElGamal::new(keypair.public_key.clone(), mode.clone());
        let plaintext = 999u32.to_biguint().unwrap();

        // Encrypt
        let original = elgamal.encrypt(&plaintext).unwrap();

        // Re-randomize multiple times
        let mut current = original.clone();
        for _ in 0..10 {
            current = elgamal.rerandomize(&current).unwrap();

            // Verify it still decrypts to the same value
            let decrypted = elgamal.decrypt(&current, &keypair.private_key).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        // Verify ciphertext changed
        assert_ne!(original, current);
    }
}

#[test]
fn test_proof_of_knowledge() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    // Prove knowledge of private key
    let proof = elgamal.prove_knowledge_of_dlog(
        keypair.private_key.secret_exponent(),
        keypair.public_key.generator(),
        keypair.public_key.public_component(),
    );

    // Verify proof
    assert!(elgamal.verify_knowledge_of_dlog(
        &proof,
        keypair.public_key.generator(),
        keypair.public_key.public_component()
    ));
}

#[test]
fn test_division_in_multiplicative_mode() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let a = 84u32.to_biguint().unwrap();
    let b = 12u32.to_biguint().unwrap();

    let ct_a = elgamal.encrypt(&a).unwrap();
    let ct_b = elgamal.encrypt(&b).unwrap();

    let ct_quotient = elgamal.homomorphic_divide(&ct_a, &ct_b).unwrap();
    let decrypted = elgamal.decrypt(&ct_quotient, &keypair.private_key).unwrap();

    // In modular arithmetic, division is multiplication by inverse
    let b_inv = vhe::utils::mod_inverse(&b, keypair.public_key.modulus()).unwrap();
    let expected = (a * b_inv) % keypair.public_key.modulus();

    assert_eq!(decrypted, expected);
}

#[test]
fn test_key_validation() {
    use vhe::PublicKey;

    // Valid key should pass
    let keypair = KeyPair::generate_for_testing(512).unwrap();
    assert!(keypair.public_key.validate().is_ok());

    // Invalid keys should fail
    let invalid_key = PublicKey::new(
        2u32.to_biguint().unwrap(),
        1u32.to_biguint().unwrap(),
        1u32.to_biguint().unwrap(),
    );
    assert!(invalid_key.validate().is_err());
}

#[test]
fn test_mode_mismatch_prevention() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();

    let elgamal_mult = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Encrypt in multiplicative mode
    let value = 42u32.to_biguint().unwrap();
    let ct_mult = elgamal_mult.encrypt(&value).unwrap();

    // Try to decrypt with additive mode (should fail)
    assert!(elgamal_add.decrypt(&ct_mult, &keypair.private_key).is_err());

    // Try homomorphic operation with mixed modes (should fail)
    let ct_add = elgamal_add.encrypt(&value).unwrap();
    assert!(elgamal_mult
        .homomorphic_operation(&ct_mult, &ct_add)
        .is_err());
}

#[test]
fn test_large_scale_operations() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Encrypt and sum 100 values
    let values: Vec<_> = (1..=100).collect();
    let ciphertexts: Vec<_> = values
        .iter()
        .map(|v| elgamal.encrypt(&v.to_biguint().unwrap()).unwrap())
        .collect();

    let sum_ct = elgamal.homomorphic_batch_operation(&ciphertexts).unwrap();
    let sum = elgamal.decrypt(&sum_ct, &keypair.private_key).unwrap();

    // Sum of 1 to 100 = 5050
    assert_eq!(sum, 5050u32.to_biguint().unwrap());
}

#[test]
fn test_verifiable_rerandomization() {
    let keypair = KeyPair::generate_for_testing(512).unwrap();
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let plaintext = 123u32.to_biguint().unwrap();
    let original = elgamal.encrypt(&plaintext).unwrap();

    // Re-randomize with proof
    let (rerandomized, proof) = elgamal.rerandomize_with_proof(&original).unwrap();

    // Verify proof
    assert!(elgamal.verify_rerandomization_proof(&original, &rerandomized, &proof));

    // Verify both decrypt to same value
    let dec1 = elgamal.decrypt(&original, &keypair.private_key).unwrap();
    let dec2 = elgamal
        .decrypt(&rerandomized, &keypair.private_key)
        .unwrap();
    assert_eq!(dec1, dec2);
    assert_eq!(dec1, plaintext);
}

#[test]
fn test_error_handling() {
    use vhe::ElGamalError;

    let keypair = KeyPair::generate_for_testing(512).unwrap();
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Test plaintext too large for additive mode
    let large_value = 10_000_000u32.to_biguint().unwrap();
    match elgamal.encrypt(&large_value) {
        Err(ElGamalError::PlaintextTooLargeForAdditive { .. }) => (),
        _ => panic!("Expected PlaintextTooLargeForAdditive error"),
    }

    // Test empty batch operation
    let empty_cts: Vec<Ciphertext> = vec![];
    match elgamal.homomorphic_batch_operation(&empty_cts) {
        Err(ElGamalError::EmptyBatch) => (),
        _ => panic!("Expected EmptyBatch error"),
    }
}

#[test]
fn test_safe_prime_generation() {
    // Test that safe prime generation works (using lenient generation for 512-bit)
    let keypair = KeyPair::load_or_generate(512);
    assert!(
        keypair.is_ok(),
        "Safe prime generation should work with lenient mode"
    );

    let keypair = keypair.unwrap();
    assert!(keypair.public_key.validate().is_ok());

    // Check that the bit size is within acceptable range (504-520 bits)
    let bit_size = keypair.public_key.bit_size();
    assert!(
        bit_size >= 504 && bit_size <= 520,
        "Bit size should be near 512, got {}",
        bit_size
    );
}
