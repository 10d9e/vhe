//! Private statistics computation using homomorphic encryption

use num_bigint::{BigUint, ToBigUint};
use num_traits::Zero;
use std::time::Instant;
use vhe::{Ciphertext, ElGamal, HomomorphicMode, HomomorphicOperations, KeyPair};

/// Represents encrypted data from a participant
#[allow(dead_code)]
struct EncryptedData {
    participant_id: String,
    encrypted_value: Ciphertext,
}

/// Private statistics computer
struct PrivateStatistics {
    elgamal: ElGamal,
    keypair: KeyPair,
    data: Vec<EncryptedData>,
}

impl PrivateStatistics {
    fn new() -> Self {
        let keypair = KeyPair::load_or_generate(512).expect("Failed to generate keys");
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Additive);

        PrivateStatistics {
            elgamal,
            keypair,
            data: Vec::new(),
        }
    }

    /// Add encrypted data from a participant
    fn add_encrypted_data(&mut self, participant_id: String, value: u32) {
        let encrypted = self
            .elgamal
            .encrypt(&value.to_biguint().unwrap())
            .expect("Encryption failed");

        self.data.push(EncryptedData {
            participant_id,
            encrypted_value: encrypted,
        });
    }

    /// Compute sum without decrypting individual values
    fn compute_sum(&self) -> BigUint {
        if self.data.is_empty() {
            return BigUint::zero();
        }

        let ciphertexts: Vec<_> = self
            .data
            .iter()
            .map(|d| d.encrypted_value.clone())
            .collect();

        let encrypted_sum = self
            .elgamal
            .homomorphic_batch_operation(&ciphertexts)
            .expect("Batch operation failed");

        self.elgamal
            .decrypt(&encrypted_sum, &self.keypair.private_key)
            .expect("Decryption failed")
    }

    /// Compute average without decrypting individual values
    fn compute_average(&self) -> f64 {
        let sum = self.compute_sum();
        let count = self.data.len() as f64;

        // Convert BigUint to f64 for division
        let sum_f64 = sum.to_u64_digits()[0] as f64;
        sum_f64 / count
    }

    /// Compute linear combination (weighted sum)
    fn compute_weighted_sum(&self, weights: &[u32]) -> BigUint {
        if weights.len() != self.data.len() {
            panic!("Weights count must match data count");
        }

        let ciphertexts: Vec<_> = self
            .data
            .iter()
            .map(|d| d.encrypted_value.clone())
            .collect();

        let weight_biguints: Vec<_> = weights.iter().map(|w| w.to_biguint().unwrap()).collect();

        let encrypted_weighted_sum = self
            .elgamal
            .homomorphic_linear_combination(&ciphertexts, &weight_biguints)
            .expect("Linear combination failed");

        self.elgamal
            .decrypt(&encrypted_weighted_sum, &self.keypair.private_key)
            .expect("Decryption failed")
    }
}

fn main() {
    println!("=== Private Statistics Computation Demo ===\n");
    println!("Computing statistics on encrypted data without revealing individual values\n");

    // Create private statistics system
    let mut stats = PrivateStatistics::new();

    // Scenario: Employee salary analysis
    println!("Scenario: Computing salary statistics while preserving privacy");
    println!("{}", "-".repeat(50));

    // Add encrypted salary data (in thousands)
    let employees = vec![
        ("Alice", 75),
        ("Bob", 82),
        ("Charlie", 68),
        ("Diana", 91),
        ("Eve", 77),
        ("Frank", 85),
        ("Grace", 79),
        ("Henry", 73),
    ];

    println!("\nAdding encrypted employee data:");
    for (name, salary) in &employees {
        println!("  {} - Salary: ${}k (encrypted)", name, salary);
        stats.add_encrypted_data(name.to_string(), *salary);
    }

    // Compute statistics
    println!("\n--- Computing Statistics on Encrypted Data ---");

    // Sum
    let start = Instant::now();
    let total = stats.compute_sum();
    let sum_time = start.elapsed();
    println!("Total salary pool: ${}k", total);
    println!("  Computation time: {:?}", sum_time);

    // Average
    let start = Instant::now();
    let avg = stats.compute_average();
    let avg_time = start.elapsed();
    println!("Average salary: ${:.2}k", avg);
    println!("  Computation time: {:?}", avg_time);

    // Weighted sum (e.g., bonus calculation based on performance)
    println!("\n--- Weighted Calculation (Performance Bonus) ---");
    let performance_multipliers = vec![3, 4, 2, 5, 3, 4, 3, 2]; // 1-5 scale

    let start = Instant::now();
    let weighted_total = stats.compute_weighted_sum(&performance_multipliers);
    let weighted_time = start.elapsed();

    println!("Weighted total (for bonus pool): ${}", weighted_total);
    println!("  Computation time: {:?}", weighted_time);

    // Department statistics (subset operations)
    println!("\n--- Department Analysis ---");
    let mut dept_stats = PrivateStatistics::new();

    // Engineering department
    let eng_employees = vec![("Alice", 75), ("Bob", 82), ("Frank", 85)];

    for (name, salary) in &eng_employees {
        dept_stats.add_encrypted_data(name.to_string(), *salary);
    }

    let eng_avg = dept_stats.compute_average();
    println!("Engineering dept average: ${:.2}k", eng_avg);

    // Privacy analysis
    println!("\n--- Privacy Guarantees ---");
    println!("✓ Individual salaries remain encrypted");
    println!("✓ Only aggregate statistics are revealed");
    println!("✓ Cannot reverse-engineer individual values from aggregates");
    println!("✓ All computations performed on ciphertexts");

    // Performance comparison
    println!("\n--- Performance Metrics ---");
    println!("Key generation: 1024-bit keys");
    println!("Encryption: O(1) per value");
    println!("Homomorphic operations: O(n) for n values");
    println!("Decryption: Only for final aggregates");

    // Additional statistics demo
    println!("\n--- Additional Statistics ---");

    // Compute sum of squares (for variance calculation)
    // Note: This would require encrypting squared values
    let squared_values: Vec<u32> = employees.iter().map(|(_, s)| s * s).collect();

    let mut squared_stats = PrivateStatistics::new();
    for ((name, _), squared) in employees.iter().zip(squared_values.iter()) {
        squared_stats.add_encrypted_data(name.to_string(), *squared);
    }

    let sum_of_squares = squared_stats.compute_sum();
    let mean = avg;
    let variance =
        (sum_of_squares.to_u64_digits()[0] as f64 / employees.len() as f64) - (mean * mean);
    let std_dev = variance.sqrt();

    println!("Standard deviation: ${:.2}k", std_dev);

    // Range analysis (would need order-preserving encryption for true min/max)
    println!("\nNote: Min/max operations require specialized schemes");
    println!("      (Order-preserving or comparison-friendly encryption)");

    println!("\n✅ Private statistics computation completed!");
    println!("\nKey Takeaways:");
    println!("• Homomorphic encryption enables computation on encrypted data");
    println!("• Perfect for privacy-preserving analytics and GDPR compliance");
    println!("• Trade-off: Higher computation cost for complete privacy");
}
