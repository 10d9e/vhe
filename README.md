# Verifiable Homomorphic Encryption

A comprehensive Rust implementation of ElGamal encryption with homomorphic properties and non-interactive zero-knowledge proofs (NIZK) for verifiable operations.

## Features

- **Dual-mode operation**: Switch between multiplicative and additive homomorphism
- **Verifiable computation**: All operations can be verified with NIZK proofs
- **Batch operations**: Efficient processing of multiple ciphertexts
- **Re-randomization**: Generate different ciphertexts for the same plaintext
- **Zero-knowledge proofs**: Prove correctness without revealing secrets
- **No trusted setup**: Unlike zk-SNARKs, no ceremony needed

## Project Structure

```
elgamal-he/
├── Cargo.toml           # Project configuration
├── README.md            # This file
├── src/
│   ├── lib.rs          # Library entry point
│   ├── error.rs        # Error types
│   ├── types.rs        # Core data structures
│   ├── utils.rs        # Utility functions
│   ├── keys.rs         # Key generation and management
│   ├── encryption.rs   # Core ElGamal operations
│   ├── homomorphic.rs  # Homomorphic operations
│   └── proofs.rs       # Zero-knowledge proofs
└── examples/
    ├── basic_encryption.rs      # Basic usage example
    ├── voting_system.rs        # Privacy-preserving voting
    ├── verifiable_computation.rs # Verifiable operations
    └── private_statistics.rs   # Private analytics

```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
elgamal-he = "0.1.0"
```

Or clone and build:

```bash
git clone https://github.com/yourusername/elgamal-he
cd elgamal-he
cargo build --release
```

## Quick Start

### Basic Encryption

```rust
use vhe::{KeyPair, ElGamal, HomomorphicMode};
use num_bigint::ToBigUint;

// Generate keys
let keypair = KeyPair::load_or_generate(1024)?;

// Create ElGamal instance
let elgamal = ElGamal::new(
    keypair.public_key.clone(),
    HomomorphicMode::Additive
);

// Encrypt values
let ct1 = elgamal.encrypt(&10u32.to_biguint().unwrap())?;
let ct2 = elgamal.encrypt(&20u32.to_biguint().unwrap())?;

// Perform homomorphic addition
let sum = elgamal.homomorphic_operation(&ct1, &ct2)?;

// Decrypt result
let result = elgamal.decrypt(&sum, &keypair.private_key)?;
assert_eq!(result, 30u32.to_biguint().unwrap());
```

### Verifiable Operations

```rust
use vhe::{VerifiableOperations, HomomorphicOperations};

// Encrypt with proof
let (ciphertext, proof) = elgamal.encrypt_with_proof(&value, None)?;

// Anyone can verify without the private key
let is_valid = elgamal.verify_encryption_proof(&ciphertext, &value, &proof);

// Perform operation with proof
let (result, op_proof) = elgamal.homomorphic_operation_with_proof(&ct1, &ct2)?;

// Verify the operation
let valid = elgamal.verify_operation_proof(&ct1, &ct2, &result, &op_proof);
```

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