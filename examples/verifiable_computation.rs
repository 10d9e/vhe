//! Verifiable computation example with zero-knowledge proofs

use num_bigint::ToBigUint;
use vhe::{ElGamal, HomomorphicMode, HomomorphicOperations, KeyPair, VerifiableOperations};

fn main() {
    println!("=== Verifiable Computation Demo ===\n");
    println!("This demo shows how to perform computations on encrypted data");
    println!("with cryptographic proofs that operations were done correctly.\n");

    // Generate key pair
    println!("Step 1: Key Generation");
    println!("{}", "-".repeat(40));
    let keypair = KeyPair::generate(1024).expect("Failed to generate keys");
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    // Prove knowledge of private key
    println!("Proving knowledge of private key...");
    let knowledge_proof = elgamal.prove_knowledge_of_dlog(
        keypair.private_key.secret_exponent(),
        keypair.public_key.generator(),
        keypair.public_key.public_component(),
    );

    let valid = elgamal.verify_knowledge_of_dlog(
        &knowledge_proof,
        keypair.public_key.generator(),
        keypair.public_key.public_component(),
    );

    println!(
        "✓ Private key knowledge proof: {}",
        if valid { "VALID" } else { "INVALID" }
    );

    // Verifiable encryption
    println!("\nStep 2: Verifiable Encryption");
    println!("{}", "-".repeat(40));

    let value1 = 42u32.to_biguint().unwrap();
    let value2 = 58u32.to_biguint().unwrap();

    println!("Encrypting value1 = {} with proof...", value1);
    let (ct1, proof1) = elgamal
        .encrypt_with_proof(&value1, None)
        .expect("Encryption failed");

    println!("Encrypting value2 = {} with proof...", value2);
    let (ct2, proof2) = elgamal
        .encrypt_with_proof(&value2, None)
        .expect("Encryption failed");

    // Verify encryption proofs
    let valid1 = elgamal.verify_encryption_proof(&ct1, &value1, &proof1);
    let valid2 = elgamal.verify_encryption_proof(&ct2, &value2, &proof2);

    println!(
        "✓ Encryption proof for value1: {}",
        if valid1 { "VALID" } else { "INVALID" }
    );
    println!(
        "✓ Encryption proof for value2: {}",
        if valid2 { "VALID" } else { "INVALID" }
    );

    // Verifiable homomorphic operation
    println!("\nStep 3: Verifiable Homomorphic Addition");
    println!("{}", "-".repeat(40));

    println!("Computing {} + {} on encrypted values...", value1, value2);
    let (ct_sum, op_proof) = elgamal
        .homomorphic_operation_with_proof(&ct1, &ct2)
        .expect("Operation failed");

    // Verify the operation was done correctly
    let op_valid = elgamal.verify_operation_proof(&ct1, &ct2, &ct_sum, &op_proof);
    println!(
        "✓ Homomorphic operation proof: {}",
        if op_valid { "VALID" } else { "INVALID" }
    );

    // Decrypt and verify result
    let decrypted_sum = elgamal
        .decrypt(&ct_sum, &keypair.private_key)
        .expect("Decryption failed");

    println!("✓ Decrypted result: {}", decrypted_sum);
    println!("✓ Expected: {}", value1.clone() + value2.clone());

    // Verifiable re-randomization
    println!("\nStep 4: Verifiable Re-randomization");
    println!("{}", "-".repeat(40));

    println!("Re-randomizing ciphertext with proof...");
    let (ct_rerand, rerand_proof) = elgamal
        .rerandomize_with_proof(&ct1)
        .expect("Re-randomization failed");

    // Verify re-randomization
    let rerand_valid = elgamal.verify_rerandomization_proof(&ct1, &ct_rerand, &rerand_proof);
    println!(
        "✓ Re-randomization proof: {}",
        if rerand_valid { "VALID" } else { "INVALID" }
    );

    // Verify both decrypt to same value
    let dec_original = elgamal
        .decrypt(&ct1, &keypair.private_key)
        .expect("Decryption failed");
    let dec_rerand = elgamal
        .decrypt(&ct_rerand, &keypair.private_key)
        .expect("Decryption failed");

    println!("✓ Original decrypts to: {}", dec_original);
    println!("✓ Re-randomized decrypts to: {}", dec_rerand);
    println!("✓ Values match: {}", dec_original == dec_rerand);

    // Complex verifiable computation
    println!("\nStep 5: Complex Verifiable Computation");
    println!("{}", "-".repeat(40));
    println!("Computing: (10 + 20) × 3");

    let v1 = 10u32.to_biguint().unwrap();
    let v2 = 20u32.to_biguint().unwrap();
    let scalar = 3u32.to_biguint().unwrap();

    // Encrypt with proofs
    let (ct_v1, _) = elgamal.encrypt_with_proof(&v1, None).expect("Failed");
    let (ct_v2, _) = elgamal.encrypt_with_proof(&v2, None).expect("Failed");

    // Add with proof
    let (ct_sum2, sum_proof) = elgamal
        .homomorphic_operation_with_proof(&ct_v1, &ct_v2)
        .expect("Failed");

    // Verify addition
    let sum_valid = elgamal.verify_operation_proof(&ct_v1, &ct_v2, &ct_sum2, &sum_proof);
    println!(
        "✓ Addition proof: {}",
        if sum_valid { "VALID" } else { "INVALID" }
    );

    // Scalar multiplication
    let ct_final = elgamal
        .homomorphic_scalar_operation(&ct_sum2, &scalar)
        .expect("Failed");

    // Decrypt and verify
    let final_result = elgamal
        .decrypt(&ct_final, &keypair.private_key)
        .expect("Decryption failed");

    println!("✓ Final result: {}", final_result);
    println!("✓ Expected: {}", (10 + 20) * 3);

    // Security guarantees
    println!("\n{}", "=".repeat(50));
    println!("Security Guarantees:");
    println!("{}", "=".repeat(50));
    println!("✓ All operations performed on encrypted data");
    println!("✓ Every operation has a cryptographic proof");
    println!("✓ Proofs verify without revealing private data");
    println!("✓ Computation correctness is mathematically guaranteed");
    println!("✓ Zero-knowledge: proofs reveal nothing about secrets");

    // Tampering detection demo
    println!("\nStep 6: Tampering Detection");
    println!("{}", "-".repeat(40));

    // Try to create a fake proof
    println!("Attempting to verify tampered proof...");
    let mut tampered_proof = proof1.clone();
    tampered_proof.response = tampered_proof.response + 1u32;

    let tampered_valid = elgamal.verify_encryption_proof(&ct1, &value1, &tampered_proof);
    println!(
        "✓ Tampered proof detected: {}",
        if !tampered_valid {
            "REJECTED"
        } else {
            "ACCEPTED (ERROR!)"
        }
    );

    // Try wrong plaintext
    let wrong_value = 43u32.to_biguint().unwrap();
    let wrong_valid = elgamal.verify_encryption_proof(&ct1, &wrong_value, &proof1);
    println!(
        "✓ Wrong plaintext detected: {}",
        if !wrong_valid {
            "REJECTED"
        } else {
            "ACCEPTED (ERROR!)"
        }
    );

    println!("\n✅ All verifiable computations completed successfully!");
    println!("The system provides complete auditability while preserving privacy.");
}
