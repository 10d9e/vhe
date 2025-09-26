# Contributing to ElGamal HE Library

Thank you for your interest in contributing to the ElGamal Homomorphic Encryption Library! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Security](#security)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful and professional in all interactions.

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Accept responsibility for mistakes
- Prioritize the community's best interests

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/elgamal-he.git
   cd elgamal-he
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/elgamal-he.git
   ```
4. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How to Contribute

### Reporting Bugs

Before reporting a bug, please:
- Check existing issues to avoid duplicates
- Collect relevant information (Rust version, OS, error messages)
- Create a minimal reproducible example

When reporting, include:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- System information
- Code samples or error logs

### Suggesting Features

Feature suggestions should include:
- Use case description
- Proposed API/implementation
- Alternative solutions considered
- Potential impacts on existing code

### Contributing Code

Areas where contributions are especially welcome:
- Performance optimizations
- Additional homomorphic operations
- New proof systems
- Documentation improvements
- Test coverage expansion
- Example applications

## Development Setup

### Prerequisites

- Rust 1.70 or higher
- Cargo
- Git

### Setup Instructions

1. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Install development tools:
   ```bash
   rustup component add rustfmt clippy
   cargo install cargo-audit cargo-tarpaulin
   ```

3. Build the project:
   ```bash
   cargo build
   ```

4. Run tests:
   ```bash
   cargo test
   ```

## Coding Standards

### Rust Style Guide

- Follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/)
- Use `cargo fmt` before committing
- Ensure `cargo clippy` passes without warnings
- Write idiomatic Rust code

### Code Organization

```rust
// Good: Clear module organization
pub mod encryption {
    pub struct ElGamal { ... }
    
    impl ElGamal {
        /// Document public methods
        pub fn encrypt(&self, plaintext: &BigUint) -> Result<Ciphertext> {
            // Implementation
        }
    }
}
```

### Naming Conventions

- Types: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Modules: `snake_case`

### Error Handling

```rust
// Good: Use Result types with descriptive errors
pub fn encrypt(&self, plaintext: &BigUint) -> Result<Ciphertext> {
    if plaintext >= &self.public_key.p {
        return Err(ElGamalError::PlaintextTooLarge);
    }
    // ...
}
```

### Comments and Documentation

```rust
/// Encrypts a plaintext message using ElGamal encryption.
/// 
/// # Arguments
/// 
/// * `plaintext` - The message to encrypt
/// 
/// # Returns
/// 
/// Returns `Ok(Ciphertext)` on success, or an error if encryption fails.
/// 
/// # Example
/// 
/// ```
/// let ciphertext = elgamal.encrypt(&plaintext)?;
/// ```
pub fn encrypt(&self, plaintext: &BigUint) -> Result<Ciphertext> {
    // Inline comments for complex logic
    // ...
}
```

## Testing

### Test Requirements

- All new features must include tests
- Maintain or improve code coverage
- Include both unit and integration tests

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption_decryption() {
        // Arrange
        let keypair = KeyPair::load_or_generate(512).unwrap();
        let elgamal = ElGamal::new(keypair.public_key.clone(), HomomorphicMode::Multiplicative);
        let plaintext = 42u32.to_biguint().unwrap();
        
        // Act
        let ciphertext = elgamal.encrypt(&plaintext).unwrap();
        let decrypted = elgamal.decrypt(&ciphertext, &keypair.private_key).unwrap();
        
        // Assert
        assert_eq!(plaintext, decrypted);
    }
}
```

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run specific test
cargo test test_encryption_decryption

# Run benchmarks
make bench
```

## Documentation

### Documentation Standards

- All public APIs must be documented
- Include examples in doc comments
- Keep documentation up-to-date with code changes
- Use clear, concise language

### Building Documentation

```bash
# Generate docs
make doc

# Check documentation
cargo doc --no-deps --all-features
```

## Pull Request Process

### Before Submitting

1. **Update your branch**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run checks**:
   ```bash
   make all  # Format, lint, build, test
   ```

3. **Update documentation**:
   - Add/update relevant documentation
   - Update README if needed
   - Add examples if applicable

### PR Guidelines

- **Title**: Use conventional commit format (e.g., `feat: add scalar division operation`)
- **Description**: Clearly describe what and why
- **Size**: Keep PRs focused and reasonably sized
- **Tests**: Include tests for new functionality
- **Documentation**: Update relevant docs

### Review Process

1. CI must pass (tests, formatting, clippy)
2. At least one maintainer review required
3. Address review feedback promptly
4. Squash commits if requested

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add homomorphic division operation
fix: correct modular inverse calculation
docs: update README examples
test: add integration tests for proofs
perf: optimize batch operations
refactor: reorganize proof module
```

## Security

### Security Considerations

When contributing cryptographic code:
- Never introduce timing side-channels
- Use constant-time operations where possible
- Validate all inputs
- Handle edge cases properly
- Consider the security implications of changes

### Reporting Security Issues

**Do not** report security vulnerabilities through public issues. Instead:

1. Email the maintainers directly
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Development Workflow

### Typical Workflow

1. **Pick an issue** or create one for discussion
2. **Fork and branch** from `main`
3. **Develop** your feature/fix
4. **Test** thoroughly
5. **Document** your changes
6. **Submit PR** with clear description
7. **Address feedback** from reviewers
8. **Celebrate** when merged! 🎉

### Quick Commands

```bash
# Development cycle
make dev       # Build and test in debug mode
make fmt       # Format code
make lint      # Run clippy
make test      # Run tests
make bench     # Run benchmarks

# Before PR
make all       # Run everything
make audit     # Security audit
```

## Questions?

If you have questions:
- Check existing issues and discussions
- Ask in the PR or issue
- Reach out to maintainers

## Recognition

Contributors will be recognized in:
- The project README
- Release notes
- GitHub contributors page

Thank you for contributing to making homomorphic encryption more accessible!