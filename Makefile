# Makefile for ElGamal HE Library

.PHONY: all build test clean doc bench fmt lint audit examples help

# Default target
all: fmt lint build test

# Build the library
build:
	@echo "Building library..."
	@cargo build --release

# Run all tests
test:
	@echo "Running tests..."
	@cargo test --all-features

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	@cargo test --test integration_tests

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@cargo clean
	@rm -rf target/

# Generate documentation
doc:
	@echo "Generating documentation..."
	@cargo doc --no-deps --all-features --open

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@cargo bench

# Format code
fmt:
	@echo "Formatting code..."
	@cargo fmt --all

# Run clippy linter
lint:
	@echo "Running clippy..."
	@cargo clippy -- -D warnings

# Security audit
audit:
	@echo "Running security audit..."
	@cargo audit

# Run all examples
examples:
	@echo "Running examples..."
	@cargo run --example basic_encryption --release
	@cargo run --example voting_system --release
	@cargo run --example verifiable_computation --release
	@cargo run --example private_statistics --release

# Run specific example
example-%:
	@echo "Running example: $*"
	@cargo run --example $* --release

# Development build (with debug info)
dev:
	@echo "Building debug version..."
	@cargo build
	@cargo test

# Check code without building
check:
	@echo "Checking code..."
	@cargo check --all-features

# Install the library locally
install:
	@echo "Installing library..."
	@cargo install --path .

# Create release build
release: fmt lint test
	@echo "Creating release build..."
	@cargo build --release
	@echo "Release build complete!"

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	@cargo tarpaulin --out Html
	@echo "Coverage report generated at target/tarpaulin/tarpaulin-report.html"

# Publish dry run
publish-dry:
	@echo "Running publish dry run..."
	@cargo publish --dry-run

# Publish to crates.io
publish: release
	@echo "Publishing to crates.io..."
	@cargo publish

# Update dependencies
update:
	@echo "Updating dependencies..."
	@cargo update

# Show dependency tree
deps:
	@cargo tree

# Quick test for CI
ci: fmt lint build test examples

# Performance profiling
profile:
	@echo "Running performance profiling..."
	@cargo build --release
	@cargo bench -- --profile-time=10

# Help
help:
	@echo "ElGamal HE Library - Makefile Commands"
	@echo ""
	@echo "Usage: make [command]"
	@echo ""
	@echo "Commands:"
	@echo "  all             - Format, lint, build, and test"
	@echo "  build           - Build the library in release mode"
	@echo "  test            - Run all tests"
	@echo "  test-integration- Run integration tests only"
	@echo "  clean           - Clean build artifacts"
	@echo "  doc             - Generate and open documentation"
	@echo "  bench           - Run benchmarks"
	@echo "  fmt             - Format code"
	@echo "  lint            - Run clippy linter"
	@echo "  audit           - Run security audit"
	@echo "  examples        - Run all examples"
	@echo "  example-NAME    - Run specific example"
	@echo "  dev             - Development build with tests"
	@echo "  check           - Check code without building"
	@echo "  install         - Install library locally"
	@echo "  release         - Create release build"
	@echo "  coverage        - Run tests with coverage"
	@echo "  publish-dry     - Dry run for publishing"
	@echo "  publish         - Publish to crates.io"
	@echo "  update          - Update dependencies"
	@echo "  deps            - Show dependency tree"
	@echo "  ci              - Run CI checks"
	@echo "  profile         - Run performance profiling"
	@echo "  help            - Show this help message"