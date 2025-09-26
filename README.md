# Verifiable Homomorphic Encryption
[![Crates.io](https://img.shields.io/crates/v/vhe)](https://crates.io/crates/vhe)
[![Build Status](https://img.shields.io/github/actions/workflow/status/10d9e/vhe/rust.yml?branch=main)](https://github.com/10d9e/vhe/actions)

Rust implementation of ElGamal homomorphic encryption with non-interactive zero-knowledge proofs (NIZK) for verifiable operations.

## Features

- **Dual-mode operation**: Switch between multiplicative and additive homomorphism
- **Operator overrides**: Use familiar `+`, `-`, `*`, `/` operators directly on ciphertexts
- **Verifiable computation**: All operations can be verified with NIZK proofs
- **Batch operations**: Efficient processing of multiple ciphertexts
- **Re-randomization**: Generate different ciphertexts for the same plaintext
- **Zero-knowledge proofs**: Prove correctness without revealing secrets
- **No trusted setup**: Unlike zk-SNARKs, no ceremony needed

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
vhe = "0.1.0"
```

Or clone and build:

```bash
git clone https://github.com/yourusername/vhe
cd vhe
cargo build --release
```

## Quick Start

### Basic Encryption with Operator Overrides

```rust
use vhe::{KeyPair, ElGamal, ElGamalOperators, HomomorphicMode};
use num_bigint::ToBigUint;

// Generate keys
let keypair = KeyPair::load_or_generate(512)?;

// Create ElGamal instance for additive operations
let elgamal = ElGamal::new(
    keypair.public_key.clone(),
    HomomorphicMode::Additive
);

// Encrypt values
let ct1 = elgamal.encrypt(&10u32.to_biguint().unwrap())?;
let ct2 = elgamal.encrypt(&20u32.to_biguint().unwrap())?;

// Wrap ciphertexts with context for operator overrides
let ctx1 = elgamal.wrap_ciphertext(ct1);
let ctx2 = elgamal.wrap_ciphertext(ct2);

// Use standard operators!
let sum = (&ctx1 + &ctx2)?;        // Addition: 10 + 20
let diff = (&ctx1 - &ctx2)?;       // Subtraction: 10 - 20
let neg = (-&ctx1)?;               // Negation: -10
let scalar_add = (&ctx1 + &5u32.to_biguint().unwrap())?; // Scalar addition: 10 + 5

// Decrypt results
let sum_result = elgamal.decrypt(&sum, &keypair.private_key)?;
let diff_result = elgamal.decrypt(&diff, &keypair.private_key)?;
let neg_result = elgamal.decrypt(&neg, &keypair.private_key)?;
let scalar_result = elgamal.decrypt(&scalar_add, &keypair.private_key)?;

assert_eq!(sum_result, 30u32.to_biguint().unwrap());
assert_eq!(scalar_result, 15u32.to_biguint().unwrap());
```

### Multiplicative Mode with Operators

```rust
// Create ElGamal instance for multiplicative operations
let elgamal_mult = ElGamal::new(
    keypair.public_key.clone(),
    HomomorphicMode::Multiplicative
);

// Encrypt values
let ct1 = elgamal_mult.encrypt(&7u32.to_biguint().unwrap())?;
let ct2 = elgamal_mult.encrypt(&3u32.to_biguint().unwrap())?;

// Wrap with context
let ctx1 = elgamal_mult.wrap_ciphertext(ct1);
let ctx2 = elgamal_mult.wrap_ciphertext(ct2);

// Use operators for multiplicative operations
let product = (&ctx1 * &ctx2)?;    // Multiplication: 7 * 3
let quotient = (&ctx1 / &ctx2)?;   // Division: 7 / 3
let power = (&ctx1 * &2u32.to_biguint().unwrap())?; // Exponentiation: 7^2

// Decrypt results
let product_result = elgamal_mult.decrypt(&product, &keypair.private_key)?;
let quotient_result = elgamal_mult.decrypt(&quotient, &keypair.private_key)?;
let power_result = elgamal_mult.decrypt(&power, &keypair.private_key)?;

assert_eq!(product_result, 21u32.to_biguint().unwrap());
assert_eq!(power_result, 49u32.to_biguint().unwrap());
```

### Verifiable Operations with Operator Overrides

```rust
use vhe::{VerifiableOperations, HomomorphicOperations, ElGamalOperators};
use num_bigint::ToBigUint;

let keypair = KeyPair::load_or_generate(512)?;
let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

// Encrypt values with proofs
let value1 = 5u32.to_biguint().unwrap();
let value2 = 3u32.to_biguint().unwrap();
let (ct1, enc_proof1) = elgamal.encrypt_with_proof(&value1, None)?;
let (ct2, enc_proof2) = elgamal.encrypt_with_proof(&value2, None)?;

// Verify encryption proofs
assert!(elgamal.verify_encryption_proof(&ct1, &value1, &enc_proof1));
assert!(elgamal.verify_encryption_proof(&ct2, &value2, &enc_proof2));

// Wrap ciphertexts with context for operator overrides
let ctx1 = elgamal.wrap_ciphertext(ct1);
let ctx2 = elgamal.wrap_ciphertext(ct2);

// Use operators for intuitive computation
let sum = (&ctx1 + &ctx2)?;        // Addition: 5 + 3
let scalar_add = (&ctx1 + &2u32.to_biguint().unwrap())?; // Scalar addition: 5 + 2

// Generate proof for the ciphertext-to-ciphertext operation
let (_, sum_proof) = elgamal.homomorphic_operation_with_proof(ctx1.ciphertext(), ctx2.ciphertext())?;

// Verify the operation proof
assert!(elgamal.verify_operation_proof(ctx1.ciphertext(), ctx2.ciphertext(), &sum, &sum_proof));

// Decrypt and verify results
let sum_result = elgamal.decrypt(&sum, &keypair.private_key)?;
let scalar_result = elgamal.decrypt(&scalar_add, &keypair.private_key)?;
assert_eq!(sum_result, 8u32.to_biguint().unwrap());
assert_eq!(scalar_result, 7u32.to_biguint().unwrap());
```

### Advanced Verifiable Computation

```rust
// Multi-step verifiable computation with operators
let values = vec![5u32, 10u32, 15u32, 20u32];
let mut ciphertexts = Vec::new();
let mut enc_proofs = Vec::new();

// Encrypt all values with proofs
for value in &values {
    let (ct, proof) = elgamal.encrypt_with_proof(&value.to_biguint().unwrap(), None)?;
    ciphertexts.push(ct);
    enc_proofs.push(proof);
}

// Verify all encryption proofs
for (i, (ct, proof)) in ciphertexts.iter().zip(enc_proofs.iter()).enumerate() {
    assert!(elgamal.verify_encryption_proof(ct, &values[i].to_biguint().unwrap(), proof));
}

// Perform verifiable aggregation using operators
let mut ctx_sum = elgamal.wrap_ciphertext(ciphertexts[0].clone());
let mut operation_proofs = Vec::new();

for i in 1..ciphertexts.len() {
    let ctx_next = elgamal.wrap_ciphertext(ciphertexts[i].clone());
    
    // Use operator for addition
    let (new_sum, op_proof) = elgamal.homomorphic_operation_with_proof(
        &ctx_sum.ciphertext, 
        &ctx_next.ciphertext
    )?;
    
    // Verify the operation
    assert!(elgamal.verify_operation_proof(
        &ctx_sum.ciphertext, 
        &ctx_next.ciphertext, 
        &new_sum, 
        &op_proof
    ));
    
    ctx_sum = elgamal.wrap_ciphertext(new_sum);
    operation_proofs.push(op_proof);
}

// Final result should be sum of all values
let final_result = elgamal.decrypt(&ctx_sum.ciphertext, &keypair.private_key)?;
let expected_sum: u32 = values.iter().sum();
assert_eq!(final_result, expected_sum.to_biguint().unwrap());
```

## Operator Overrides

The library provides intuitive operator overrides that make homomorphic operations feel natural:

### CiphertextWithContext

The recommended approach uses `CiphertextWithContext` to wrap ciphertexts with their ElGamal context:

```rust
use vhe::{ElGamal, ElGamalOperators, HomomorphicMode, KeyPair};
use num_bigint::ToBigUint;

let keypair = KeyPair::load_or_generate(512)?;
let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

// Encrypt and wrap with context
let ct1 = elgamal.encrypt(&5u32.to_biguint().unwrap())?;
let ct2 = elgamal.encrypt(&3u32.to_biguint().unwrap())?;
let ctx1 = elgamal.wrap_ciphertext(ct1);
let ctx2 = elgamal.wrap_ciphertext(ct2);

// Use standard operators!
let sum = (&ctx1 + &ctx2)?;        // Addition
let diff = (&ctx1 - &ctx2)?;       // Subtraction
let neg = (-&ctx1)?;               // Negation
let scalar_add = (&ctx1 + &2u32.to_biguint().unwrap())?; // Scalar addition
let scalar_mul = (&ctx1 * &2u32.to_biguint().unwrap())?; // Scalar multiplication
```

### Operators with Verifiable Proofs

You can combine the intuitive operator syntax with verifiable operations:

```rust
use vhe::{VerifiableOperations, ElGamalOperators};

// Encrypt with proofs
let (ct1, enc_proof1) = elgamal.encrypt_with_proof(&5u32.to_biguint().unwrap(), None)?;
let (ct2, enc_proof2) = elgamal.encrypt_with_proof(&3u32.to_biguint().unwrap(), None)?;

// Verify encryption proofs
assert!(elgamal.verify_encryption_proof(&ct1, &5u32.to_biguint().unwrap(), &enc_proof1));
assert!(elgamal.verify_encryption_proof(&ct2, &3u32.to_biguint().unwrap(), &enc_proof2));

// Wrap with context for operators
let ctx1 = elgamal.wrap_ciphertext(ct1);
let ctx2 = elgamal.wrap_ciphertext(ct2);

// Use operators for the computation
let sum = (&ctx1 + &ctx2)?;        // Intuitive syntax
let diff = (&ctx1 - &ctx2)?;       // Clean and readable

// Generate proof for the operation (ciphertext-to-ciphertext only)
let (_, sum_proof) = elgamal.homomorphic_operation_with_proof(ctx1.ciphertext(), ctx2.ciphertext())?;

// Verify the operation proof
assert!(elgamal.verify_operation_proof(ctx1.ciphertext(), ctx2.ciphertext(), &sum, &sum_proof));

// Decrypt and verify results
let sum_result = elgamal.decrypt(&sum, &keypair.private_key)?;
let diff_result = elgamal.decrypt(&diff, &keypair.private_key)?;
assert_eq!(sum_result, 8u32.to_biguint().unwrap());
assert_eq!(diff_result, 2u32.to_biguint().unwrap());
```

This approach gives you the best of both worlds:
- **Intuitive operators** for clean, readable code
- **Verifiable proofs** for ciphertext-to-ciphertext operations
- **Full auditability** of all operations
- **Note**: Scalar operations use operators for convenience but don't generate verifiable proofs

## Homomorphic Modes

### Multiplicative Mode
- **Operation**: `Enc(a) × Enc(b) = Enc(a × b)`
- **Use cases**: Product aggregation, RSA-like operations
- **Message space**: Full range [0, p-1]

### Additive Mode
- **Operation**: `Enc(a) ⊗ Enc(b) = Enc(a + b)`
- **Use cases**: Voting, statistics, counters
- **Message space**: Limited (configurable, default 1M)

## Available Operations

| Operation | Multiplicative Mode | Additive Mode |
|-----------|-------------------|---------------|
| Basic Operation | Multiplication | Addition |
| Scalar Operation | Exponentiation | Scalar Multiplication |
| Division | ✓ | ✗ |
| Subtraction | ✗ | ✓ |
| Negation | ✗ | ✓ |
| Batch Operations | ✓ | ✓ |
| Linear Combination | ✗ | ✓ |
| Re-randomization | ✓ | ✓ |

## Zero-Knowledge Proofs

The library includes several NIZK proof types:

1. **Proof of Knowledge**: Prove you know a secret without revealing it
2. **Proof of Correct Encryption**: Prove a ciphertext encrypts a specific plaintext
3. **Proof of Equality**: Prove two ciphertexts encrypt the same value
4. **Proof of Correct Operation**: Prove operations were performed correctly
5. **Proof of Re-randomization**: Prove ciphertext was correctly re-randomized

## Running Examples

```bash
# Basic encryption demo
cargo run --example basic_encryption

# Operator overrides demonstration
cargo run --example operator_overrides

# Verifiable operators with proofs
cargo run --example verifiable_operators

# Privacy-preserving voting system
cargo run --example voting_system

# Verifiable computation with proofs
cargo run --example verifiable_computation

# Private statistics computation
cargo run --example private_statistics
```

## Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

## Security Considerations

- **Discrete Log Assumption**: Security based on hardness of discrete logarithm
- **Random Oracle Model**: Proofs rely on hash function as random oracle
- **Safe Primes**: Uses safe primes (p = 2q + 1) for strong security
- **No Trusted Setup**: Unlike zk-SNARKs, no ceremony or trusted parameters needed

## Performance

- **Key Generation**: ~100-500ms for 1024-bit keys
- **Encryption**: ~5-10ms per value
- **Homomorphic Operations**: ~1-2ms per operation
- **Proof Generation**: ~10-20ms per proof
- **Proof Verification**: ~5-10ms per verification

## Use Cases

- **E-Voting**: Privacy-preserving electronic voting
- **Private Analytics**: Compute statistics without accessing raw data
- **Secure Auctions**: Sealed-bid auctions with verifiable fairness
- **GDPR Compliance**: Process encrypted personal data
- **Multi-party Computation**: Collaborative computation without sharing inputs
- **Blockchain**: Private smart contracts and confidential transactions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is dual-licensed under MIT OR Apache-2.0.

## References

- [ElGamal Encryption](https://en.wikipedia.org/wiki/ElGamal_encryption)
- [Exponential ElGamal](https://crypto.stanford.edu/pbc/notes/crypto/additive.html)
- [Schnorr Identification Protocol](https://en.wikipedia.org/wiki/Schnorr_signature)
- [Chaum-Pedersen Protocol](https://link.springer.com/chapter/10.1007/3-540-48285-7_24)
- [Fiat-Shamir Heuristic](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic)

## Contact

For questions or suggestions, please open an issue on GitHub.