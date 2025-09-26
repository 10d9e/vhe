//! Example demonstrating operator overrides with verifiable proofs

use num_bigint::ToBigUint;
use vhe::{ElGamal, ElGamalOperators, HomomorphicMode, KeyPair, VerifiableOperations};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Verifiable Operators Demo ===\n");

    // Generate keys
    println!("Generating 512-bit key pair...");
    let keypair = KeyPair::load_or_generate(512)?;
    println!("✓ Keys generated successfully\n");

    // Test additive mode with verifiable operations
    println!("=== Additive Mode with Verifiable Proofs ===");
    test_additive_verifiable_operators(&keypair)?;

    println!("\n=== Multiplicative Mode with Verifiable Proofs ===");
    test_multiplicative_verifiable_operators(&keypair)?;

    println!("\n✓ All verifiable operator tests completed successfully!");
    Ok(())
}

fn test_additive_verifiable_operators(keypair: &KeyPair) -> Result<(), Box<dyn std::error::Error>> {
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Use small values to avoid discrete log issues
    let m1 = 5u32.to_biguint().unwrap();
    let m2 = 3u32.to_biguint().unwrap();
    let scalar = 2u32.to_biguint().unwrap();

    println!(
        "Plaintext values: m1 = {}, m2 = {}, scalar = {}",
        m1, m2, scalar
    );

    // Encrypt values with proofs
    let (ct1, enc_proof1) = elgamal.encrypt_with_proof(&m1, None)?;
    let (ct2, enc_proof2) = elgamal.encrypt_with_proof(&m2, None)?;

    // Verify encryption proofs
    assert!(elgamal.verify_encryption_proof(&ct1, &m1, &enc_proof1));
    assert!(elgamal.verify_encryption_proof(&ct2, &m2, &enc_proof2));
    println!("✓ Encryption proofs verified");

    // Wrap ciphertexts with context for operator overrides
    let ctx1 = elgamal.wrap_ciphertext(ct1);
    let ctx2 = elgamal.wrap_ciphertext(ct2);

    // Use operators for the computation
    let sum = (&ctx1 + &ctx2)?; // Addition: 5 + 3
    let scalar_add = (&ctx1 + &scalar)?; // Scalar addition: 5 + 2
    let scalar_mul = (&ctx1 * &scalar)?; // Scalar multiplication: 5 * 2

    // Generate proof for ciphertext-to-ciphertext operation
    let (_, sum_proof) =
        elgamal.homomorphic_operation_with_proof(ctx1.ciphertext(), ctx2.ciphertext())?;

    // Verify the operation proof
    assert!(elgamal.verify_operation_proof(ctx1.ciphertext(), ctx2.ciphertext(), &sum, &sum_proof));
    println!("✓ Operation proof verified");

    // Decrypt and verify results
    let sum_result = elgamal.decrypt(&sum, &keypair.private_key)?;
    let scalar_add_result = elgamal.decrypt(&scalar_add, &keypair.private_key)?;
    let scalar_mul_result = elgamal.decrypt(&scalar_mul, &keypair.private_key)?;

    println!(
        "Addition: {} + {} = {} (expected: {})",
        m1,
        m2,
        sum_result,
        &m1 + &m2
    );
    println!(
        "Scalar addition: {} + {} = {} (expected: {})",
        m1,
        scalar,
        scalar_add_result,
        &m1 + &scalar
    );
    println!(
        "Scalar multiplication: {} * {} = {} (expected: {})",
        m1,
        scalar,
        scalar_mul_result,
        &m1 * &scalar
    );

    Ok(())
}

fn test_multiplicative_verifiable_operators(
    keypair: &KeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let m1 = 3u32.to_biguint().unwrap();
    let m2 = 2u32.to_biguint().unwrap();
    let scalar = 2u32.to_biguint().unwrap();

    println!(
        "Plaintext values: m1 = {}, m2 = {}, scalar = {}",
        m1, m2, scalar
    );

    // Encrypt values with proofs
    let (ct1, enc_proof1) = elgamal.encrypt_with_proof(&m1, None)?;
    let (ct2, enc_proof2) = elgamal.encrypt_with_proof(&m2, None)?;

    // Verify encryption proofs
    assert!(elgamal.verify_encryption_proof(&ct1, &m1, &enc_proof1));
    assert!(elgamal.verify_encryption_proof(&ct2, &m2, &enc_proof2));
    println!("✓ Encryption proofs verified");

    // Wrap ciphertexts with context for operator overrides
    let ctx1 = elgamal.wrap_ciphertext(ct1);
    let ctx2 = elgamal.wrap_ciphertext(ct2);

    // Use operators for multiplicative operations
    let product = (&ctx1 * &ctx2)?; // Multiplication: 3 * 2
    let quotient = (&ctx1 / &ctx2)?; // Division: 3 / 2
    let power = (&ctx1 * &scalar)?; // Exponentiation: 3^2

    // Generate proof for ciphertext-to-ciphertext operation
    let (_, product_proof) =
        elgamal.homomorphic_operation_with_proof(ctx1.ciphertext(), ctx2.ciphertext())?;

    // Verify the operation proof
    assert!(elgamal.verify_operation_proof(
        ctx1.ciphertext(),
        ctx2.ciphertext(),
        &product,
        &product_proof
    ));
    println!("✓ Operation proof verified");

    // Decrypt and verify results
    let product_result = elgamal.decrypt(&product, &keypair.private_key)?;
    let quotient_result = elgamal.decrypt(&quotient, &keypair.private_key)?;
    let power_result = elgamal.decrypt(&power, &keypair.private_key)?;

    println!(
        "Multiplication: {} * {} = {} (expected: {})",
        m1,
        m2,
        product_result,
        (&m1 * &m2) % elgamal.public_key.modulus()
    );
    println!(
        "Division: {} / {} = {} (expected: {})",
        m1,
        m2,
        quotient_result,
        (&m1 * vhe::utils::mod_inverse(&m2, elgamal.public_key.modulus()).unwrap())
            % elgamal.public_key.modulus()
    );
    println!(
        "Exponentiation: {} ^ {} = {} (expected: {})",
        m1,
        scalar,
        power_result,
        vhe::utils::mod_exp(&m1, &scalar, elgamal.public_key.modulus())
    );

    Ok(())
}
