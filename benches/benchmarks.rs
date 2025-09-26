//! Performance benchmarks for ElGamal operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::ToBigUint;
use vhe::{ElGamal, HomomorphicMode, HomomorphicOperations, KeyPair, VerifiableOperations};

fn benchmark_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    for bits in [512, 1024, 2048].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(bits), bits, |b, &bits| {
            b.iter(|| KeyPair::load_or_generate(bits).expect("Failed to generate keys"));
        });
    }

    group.finish();
}

fn benchmark_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");

    let keypair = KeyPair::load_or_generate(1024).expect("Failed to generate keys");
    let plaintext = 42u32.to_biguint().unwrap();

    // Benchmark multiplicative mode
    let elgamal_mult = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    group.bench_function("multiplicative_mode", |b| {
        b.iter(|| {
            elgamal_mult
                .encrypt(black_box(&plaintext))
                .expect("Encryption failed")
        });
    });

    // Benchmark additive mode
    let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    group.bench_function("additive_mode", |b| {
        b.iter(|| {
            elgamal_add
                .encrypt(black_box(&plaintext))
                .expect("Encryption failed")
        });
    });

    group.finish();
}

fn benchmark_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("decryption");

    let keypair = KeyPair::load_or_generate(1024).expect("Failed to generate keys");
    let plaintext = 42u32.to_biguint().unwrap();

    // Multiplicative mode
    let elgamal_mult = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);
    let ct_mult = elgamal_mult.encrypt(&plaintext).expect("Encryption failed");

    group.bench_function("multiplicative_mode", |b| {
        b.iter(|| {
            elgamal_mult
                .decrypt(black_box(&ct_mult), black_box(&keypair.private_key))
                .expect("Decryption failed")
        });
    });

    // Additive mode
    let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);
    let ct_add = elgamal_add.encrypt(&plaintext).expect("Encryption failed");

    group.bench_function("additive_mode", |b| {
        b.iter(|| {
            elgamal_add
                .decrypt(black_box(&ct_add), black_box(&keypair.private_key))
                .expect("Decryption failed")
        });
    });

    group.finish();
}

fn benchmark_homomorphic_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("homomorphic_operations");

    let keypair = KeyPair::load_or_generate(1024).expect("Failed to generate keys");

    // Multiplicative mode
    let elgamal_mult = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let m1 = 7u32.to_biguint().unwrap();
    let m2 = 6u32.to_biguint().unwrap();
    let ct1_mult = elgamal_mult.encrypt(&m1).expect("Encryption failed");
    let ct2_mult = elgamal_mult.encrypt(&m2).expect("Encryption failed");

    group.bench_function("multiplication", |b| {
        b.iter(|| {
            elgamal_mult
                .homomorphic_operation(black_box(&ct1_mult), black_box(&ct2_mult))
                .expect("Operation failed")
        });
    });

    // Additive mode
    let elgamal_add = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    let ct1_add = elgamal_add.encrypt(&m1).expect("Encryption failed");
    let ct2_add = elgamal_add.encrypt(&m2).expect("Encryption failed");

    group.bench_function("addition", |b| {
        b.iter(|| {
            elgamal_add
                .homomorphic_operation(black_box(&ct1_add), black_box(&ct2_add))
                .expect("Operation failed")
        });
    });

    // Scalar operations
    let scalar = 3u32.to_biguint().unwrap();

    group.bench_function("scalar_multiplication", |b| {
        b.iter(|| {
            elgamal_add
                .homomorphic_scalar_operation(black_box(&ct1_add), black_box(&scalar))
                .expect("Operation failed")
        });
    });

    group.finish();
}

fn benchmark_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");

    let keypair = KeyPair::load_or_generate(1024).expect("Failed to generate keys");
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

    for size in [10, 50, 100].iter() {
        let ciphertexts: Vec<_> = (0..*size)
            .map(|i| {
                elgamal
                    .encrypt(&i.to_biguint().unwrap())
                    .expect("Encryption failed")
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertexts, |b, cts| {
            b.iter(|| {
                elgamal
                    .homomorphic_batch_operation(black_box(cts))
                    .expect("Batch operation failed")
            });
        });
    }

    group.finish();
}

fn benchmark_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_knowledge_proofs");

    let keypair = KeyPair::load_or_generate(1024).expect("Failed to generate keys");
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let plaintext = 42u32.to_biguint().unwrap();

    // Benchmark proof generation
    group.bench_function("proof_generation", |b| {
        b.iter(|| {
            elgamal
                .encrypt_with_proof(black_box(&plaintext), None)
                .expect("Proof generation failed")
        });
    });

    // Benchmark proof verification
    let (ciphertext, proof) = elgamal
        .encrypt_with_proof(&plaintext, None)
        .expect("Encryption with proof failed");

    group.bench_function("proof_verification", |b| {
        b.iter(|| {
            elgamal.verify_encryption_proof(
                black_box(&ciphertext),
                black_box(&plaintext),
                black_box(&proof),
            )
        });
    });

    // Benchmark operation proof
    let ct1 = elgamal.encrypt(&plaintext).expect("Encryption failed");
    let ct2 = elgamal.encrypt(&plaintext).expect("Encryption failed");

    group.bench_function("operation_proof_generation", |b| {
        b.iter(|| {
            elgamal
                .homomorphic_operation_with_proof(black_box(&ct1), black_box(&ct2))
                .expect("Operation proof failed")
        });
    });

    group.finish();
}

fn benchmark_rerandomization(c: &mut Criterion) {
    let keypair = KeyPair::load_or_generate(1024).expect("Failed to generate keys");
    let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);

    let plaintext = 100u32.to_biguint().unwrap();
    let ciphertext = elgamal.encrypt(&plaintext).expect("Encryption failed");

    c.bench_function("rerandomization", |b| {
        b.iter(|| {
            elgamal
                .rerandomize(black_box(&ciphertext))
                .expect("Rerandomization failed")
        });
    });
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_encryption,
    benchmark_decryption,
    benchmark_homomorphic_operations,
    benchmark_batch_operations,
    benchmark_proofs,
    benchmark_rerandomization
);

criterion_main!(benches);
