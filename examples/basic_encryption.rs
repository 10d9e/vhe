//! Basic ElGamal encryption and decryption example

use num_bigint::ToBigUint;
use vhe::{ElGamal, HomomorphicMode, KeyPair};

fn main() {
    println!("=== Basic ElGamal Encryption Demo ===\n");

    // Generate a key pair
    println!("Generating 1024-bit key pair...");
    let keypair = KeyPair::generate(1024).expect("Failed to generate keys");
    println!("✓ Keys generated successfully");
    println!("  Public key size: {} bits", keypair.public_key.bit_size());

    // Multiplicative mode example
    println!("\n--- Multiplicative Mode ---");
    let elgamal_mult = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    // Encrypt some values
    let value1 = 15u32.to_biguint().unwrap();
    let value2 = 7u32.to_biguint().unwrap();

    println!("Encrypting value1 = {}", value1);
    let ct1 = elgamal_mult.encrypt(&value1).expect("Encryption failed");

    println!("Encrypting value2 = {}", value2);
    let ct2 = elgamal_mult.encrypt(&value2).expect("Encryption failed");

    println!("Ciphertext sizes: {} bytes each", ct1.size_bytes());

    // Perform homomorphic multiplication
    use vhe::HomomorphicOperations;
    let ct_product = elgamal_mult
        .homomorphic_operation(&ct1, &ct2)
        .expect("Homomorphic operation failed");

    // Decrypt the result
    let decrypted = elgamal_mult
        .decrypt(&ct_product, &keypair.private_key)
        .expect("Decryption failed");

    println!(
        "Homomorphic multiplication: {} × {} = {}",
        value1, value2, decrypted
    );

    // Additive mode example
    println!("\n--- Additive Mode ---");
    let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    let value3 = 25u32.to_biguint().unwrap();
    let value4 = 17u32.to_biguint().unwrap();

    println!("Encrypting value3 = {}", value3);
    let ct3 = elgamal_add.encrypt(&value3).expect("Encryption failed");

    println!("Encrypting value4 = {}", value4);
    let ct4 = elgamal_add.encrypt(&value4).expect("Encryption failed");

    // Perform homomorphic addition
    let ct_sum = elgamal_add
        .homomorphic_operation(&ct3, &ct4)
        .expect("Homomorphic operation failed");

    // Decrypt the result
    let decrypted_sum = elgamal_add
        .decrypt(&ct_sum, &keypair.private_key)
        .expect("Decryption failed");

    println!(
        "Homomorphic addition: {} + {} = {}",
        value3, value4, decrypted_sum
    );

    // Demonstrate re-randomization
    println!("\n--- Re-randomization ---");
    let original = elgamal_mult.encrypt(&value1).expect("Encryption failed");
    let rerandomized = elgamal_mult
        .rerandomize(&original)
        .expect("Re-randomization failed");

    println!(
        "Original and re-randomized ciphertexts are different: {}",
        original != rerandomized
    );

    let dec_original = elgamal_mult
        .decrypt(&original, &keypair.private_key)
        .expect("Decryption failed");
    let dec_rerand = elgamal_mult
        .decrypt(&rerandomized, &keypair.private_key)
        .expect("Decryption failed");

    println!(
        "Both decrypt to the same value: {} = {}",
        dec_original, dec_rerand
    );

    println!("\n✅ Demo completed successfully!");
}
