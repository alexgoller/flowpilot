#!/usr/bin/env bash
# Host driver: build Linux binaries in Docker, then run the differential test in a container.
# Usage: tests/e2e/run.sh [SCENARIO_SECS | unmanaged | envonly]     (needs Docker with linux/amd64 emulation)
# `unmanaged` runs the unmanaged-workload scenario against a mock PCE instead (about 6 minutes).
# `envonly` runs FlowPilot configured by FLOWPILOT_* variables only, against a mock PCE (about 6 minutes).
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
# The traffic generator is https://github.com/alexgoller/illumio-flowgen, checked out next to this repository.
FLOWGEN_SRC=${FLOWGEN_SRC:-$REPO/../illumio-flowgen}
IMAGE=rust:1-bookworm
OUT=$REPO/target/e2e

docker run --rm --platform linux/amd64 \
  -v "$REPO":/src/flowpilot -v "$FLOWGEN_SRC":/src/flowgen:ro \
  -v flowlink-cargo-registry:/usr/local/cargo/registry \
  "$IMAGE" bash -c '
    set -e
    cd /src/flowpilot && CARGO_TARGET_DIR=target/linux-amd64 cargo build --release --quiet
    cd /src/flowgen && CARGO_TARGET_DIR=/src/flowpilot/target/flowgen-linux-amd64 cargo build --release --quiet --locked'

if [ "${1:-}" = unmanaged ] || [ "${1:-}" = envonly ]; then
  docker run --rm --platform linux/amd64 -v "$REPO":/w:ro -v "$REPO/target":/w/target \
    "$IMAGE" bash "/w/tests/e2e/$1.sh" \
      /w/target/linux-amd64/release/flowpilot \
      /w/target/flowgen-linux-amd64/release/flowgen \
      "/w/target/e2e-$1"
  echo "artifacts: $REPO/target/e2e-$1"
  exit 0
fi

docker run --rm --platform linux/amd64 -v "$REPO":/w:ro -v "$REPO/target":/w/target \
  "$IMAGE" bash /w/tests/e2e/inside.sh \
    /w/original/usr/local/bin/flowlink \
    /w/target/linux-amd64/release/flowpilot \
    /w/target/flowgen-linux-amd64/release/flowgen \
    /w/target/e2e "${1:-10}"
echo "artifacts: $OUT"
