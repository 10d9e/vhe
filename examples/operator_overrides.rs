//! Example demonstrating operator overrides for homomorphic operations

use num_bigint::ToBigUint;
use vhe::{ElGamal, HomomorphicMode, KeyPair};

fn main() {
    println!("=== Operator Overrides Demo ===\n");

    // Generate keys
    println!("Generating 512-bit key pair...");
    let keypair = KeyPair::load_or_generate(512).expect("Failed to generate keys");
    println!("✓ Keys generated successfully\n");

    // Test additive mode with operators
    println!("=== Additive Mode Operations ===");
    test_additive_operators(&keypair);

    println!("\n=== Multiplicative Mode Operations ===");
    test_multiplicative_operators(&keypair);

    println!("\n=== Scalar Operations ===");
    test_scalar_operations(&keypair);

    println!("\n=== Error Handling ===");
    test_error_handling(&keypair);

    println!("\n✓ All operator override tests completed successfully!");
}

fn test_additive_operators(keypair: &KeyPair) {
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    let m1 = 15u32.to_biguint().unwrap();
    let m2 = 25u32.to_biguint().unwrap();

    println!("Plaintext values: m1 = {}, m2 = {}", m1, m2);

    // Encrypt values
    let ctx1 = elgamal.encrypt_with_context(&m1).unwrap();
    let ctx2 = elgamal.encrypt_with_context(&m2).unwrap();

    // Test addition: ct1 + ct2
    let ct_sum = (&ctx1 + &ctx2).unwrap();
    let decrypted_sum = elgamal.decrypt(&ct_sum, &keypair.private_key).unwrap();
    println!(
        "Addition: {} + {} = {} (expected: {})",
        m1,
        m2,
        decrypted_sum,
        &m1 + &m2
    );

    // Test subtraction: ct1 - ct2
    let ct_diff = (&ctx1 - &ctx2).unwrap();
    let decrypted_diff = elgamal.decrypt(&ct_diff, &keypair.private_key).unwrap();
    let expected_diff = (&m1 + elgamal.public_key.modulus() - &m2) % elgamal.public_key.modulus();
    println!(
        "Subtraction: {} - {} = {} (expected: {})",
        m1, m2, decrypted_diff, expected_diff
    );

    // Test negation: -ct1
    let ct_neg = (-&ctx1).unwrap();
    let decrypted_neg = elgamal.decrypt(&ct_neg, &keypair.private_key).unwrap();
    let expected_neg = (elgamal.public_key.modulus() - &m1) % elgamal.public_key.modulus();
    println!(
        "Negation: -{} = {} (expected: {})",
        m1, decrypted_neg, expected_neg
    );
}

fn test_multiplicative_operators(keypair: &KeyPair) {
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let m1 = 7u32.to_biguint().unwrap();
    let m2 = 6u32.to_biguint().unwrap();

    println!("Plaintext values: m1 = {}, m2 = {}", m1, m2);

    // Encrypt values
    let ctx1 = elgamal.encrypt_with_context(&m1).unwrap();
    let ctx2 = elgamal.encrypt_with_context(&m2).unwrap();

    // Test multiplication: ct1 * ct2
    let ct_product = (&ctx1 * &ctx2).unwrap();
    let decrypted_product = elgamal.decrypt(&ct_product, &keypair.private_key).unwrap();
    println!(
        "Multiplication: {} * {} = {} (expected: {})",
        m1,
        m2,
        decrypted_product,
        (&m1 * &m2) % elgamal.public_key.modulus()
    );

    // Test division: ct1 / ct2
    let ct_quotient = (&ctx1 / &ctx2).unwrap();
    let decrypted_quotient = elgamal.decrypt(&ct_quotient, &keypair.private_key).unwrap();
    let m2_inv = vhe::utils::mod_inverse(&m2, elgamal.public_key.modulus()).unwrap();
    let expected_quotient = (&m1 * &m2_inv) % elgamal.public_key.modulus();
    println!(
        "Division: {} / {} = {} (expected: {})",
        m1, m2, decrypted_quotient, expected_quotient
    );
}

fn test_scalar_operations(keypair: &KeyPair) {
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    let m = 20u32.to_biguint().unwrap();
    let scalar = 5u32.to_biguint().unwrap();

    println!("Plaintext: m = {}, scalar = {}", m, scalar);

    // Encrypt value
    let ctx = elgamal.encrypt_with_context(&m).unwrap();

    // Test scalar addition: ct + scalar
    let ct_scalar_add = (&ctx + &scalar).unwrap();
    let decrypted_scalar_add = elgamal
        .decrypt(&ct_scalar_add, &keypair.private_key)
        .unwrap();
    println!(
        "Scalar addition: {} + {} = {} (expected: {})",
        m,
        scalar,
        decrypted_scalar_add,
        (&m + &scalar) % elgamal.public_key.modulus()
    );

    // Test scalar subtraction: ct - scalar
    let ct_scalar_sub = (&ctx - &scalar).unwrap();
    let decrypted_scalar_sub = elgamal
        .decrypt(&ct_scalar_sub, &keypair.private_key)
        .unwrap();
    let expected_sub = (&m + elgamal.public_key.modulus() - &scalar) % elgamal.public_key.modulus();
    println!(
        "Scalar subtraction: {} - {} = {} (expected: {})",
        m, scalar, decrypted_scalar_sub, expected_sub
    );

    // Test scalar multiplication: ct * scalar
    let ct_scalar_mul = (&ctx * &scalar).unwrap();
    let decrypted_scalar_mul = elgamal
        .decrypt(&ct_scalar_mul, &keypair.private_key)
        .unwrap();
    println!(
        "Scalar multiplication: {} * {} = {} (expected: {})",
        m,
        scalar,
        decrypted_scalar_mul,
        (&m * &scalar) % elgamal.public_key.modulus()
    );
}

fn test_error_handling(keypair: &KeyPair) {
    let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);
    let elgamal_mult = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let m1 = 10u32.to_biguint().unwrap();
    let m2 = 5u32.to_biguint().unwrap();
    let scalar = 2u32.to_biguint().unwrap();

    // Test that division fails in additive mode
    let ctx1_add = elgamal_add.encrypt_with_context(&m1).unwrap();
    let ctx2_add = elgamal_add.encrypt_with_context(&m2).unwrap();
    let division_result = &ctx1_add / &ctx2_add;
    println!("Division in additive mode: {:?}", division_result.is_err());

    // Test that subtraction fails in multiplicative mode
    let ctx1_mult = elgamal_mult.encrypt_with_context(&m1).unwrap();
    let ctx2_mult = elgamal_mult.encrypt_with_context(&m2).unwrap();
    let subtraction_result = &ctx1_mult - &ctx2_mult;
    println!(
        "Subtraction in multiplicative mode: {:?}",
        subtraction_result.is_err()
    );

    // Test that scalar division fails in additive mode
    let scalar_div_result = &ctx1_add / &scalar;
    println!(
        "Scalar division in additive mode: {:?}",
        scalar_div_result.is_err()
    );

    // Test that scalar addition fails in multiplicative mode
    let ctx1_mult_scalar = elgamal_mult.encrypt_with_context(&m1).unwrap();
    let scalar_add_result = &ctx1_mult_scalar + &scalar;
    println!(
        "Scalar addition in multiplicative mode: {:?}",
        scalar_add_result.is_err()
    );
}
