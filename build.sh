#!/bin/bash

# Build script for ElGamal HE Library

echo "Building ElGamal Homomorphic Encryption Library..."
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Cargo is not installed${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
cargo clean

# Format code
echo -e "${YELLOW}Formatting code...${NC}"
cargo fmt

# Run clippy for linting
echo -e "${YELLOW}Running clippy...${NC}"
cargo clippy -- -D warnings

# Build the library
echo -e "${YELLOW}Building library...${NC}"
cargo build --release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Library built successfully${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
cargo test

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi

# Build documentation
echo -e "${YELLOW}Building documentation...${NC}"
cargo doc --no-deps

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Documentation built successfully${NC}"
    echo "View documentation at: target/doc/elgamal_he/index.html"
else
    echo -e "${RED}✗ Documentation build failed${NC}"
fi

# Run examples
echo -e "${YELLOW}Running examples...${NC}"

for example in basic_encryption voting_system verifiable_computation private_statistics; do
    echo -e "${YELLOW}Running example: $example${NC}"
    cargo run --example $example --release > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}  ✓ $example completed successfully${NC}"
    else
        echo -e "${RED}  ✗ $example failed${NC}"
    fi
done

echo ""
echo -e "${GREEN}Build complete!${NC}"
echo ""
echo "Next steps:"
echo "  - View documentation: open target/doc/elgamal_he/index.html"
echo "  - Run examples: cargo run --example <example_name>"
echo "  - Run benchmarks: cargo bench"