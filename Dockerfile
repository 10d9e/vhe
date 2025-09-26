# Multi-stage Dockerfile for ElGamal HE Library

# Stage 1: Builder
FROM rust:1.90.0-slim AS builder

# Install required dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a new empty shell project
WORKDIR /usr/src
RUN USER=root cargo new --lib elgamal-he
WORKDIR /usr/src/elgamal-he

# Copy manifests
COPY Cargo.toml ./

# Cache dependencies
RUN cargo build --release --lib
RUN rm src/*.rs target/release/deps/elgamal_he*

# Copy source code
COPY src ./src
COPY benches ./benches
COPY examples ./examples
COPY tests ./tests

# Build the library and examples
RUN cargo build --release --lib
RUN cargo build --release --examples

# Run tests
RUN cargo test --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the built library and examples
COPY --from=builder /usr/src/elgamal-he/target/release/examples/* /usr/local/bin/

# Create a non-root user
RUN useradd -m -u 1000 elgamal && \
    mkdir -p /home/elgamal/data && \
    chown -R elgamal:elgamal /home/elgamal

USER elgamal
WORKDIR /home/elgamal

# Default command shows available examples
CMD echo "Available examples:" && \
    echo "  - basic_encryption" && \
    echo "  - voting_system" && \
    echo "  - verifiable_computation" && \
    echo "  - private_statistics" && \
    echo "" && \
    echo "Run with: docker run -it elgamal-he <example_name>"