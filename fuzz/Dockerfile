# Fuzzing image: nightly Rust + cargo-fuzz (libFuzzer). Native on arm64 and amd64.
# Build from the repository root: docker build -t flowpilot-fuzz fuzz/
FROM rustlang/rust:nightly
RUN cargo install cargo-fuzz --locked
WORKDIR /work
