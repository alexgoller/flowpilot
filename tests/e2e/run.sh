#!/usr/bin/env bash
# Host driver: build Linux binaries in Docker, then run the differential test in a container.
# Usage: tests/e2e/run.sh [SCENARIO_SECS | unmanaged | envonly | kafka-out | kafka-pilot]
#        (needs Docker with linux/amd64 emulation)
# `unmanaged` runs the unmanaged-workload scenario against a mock PCE instead (about 6 minutes).
# `envonly` runs FlowPilot configured by FLOWPILOT_* variables only, against a mock PCE (about 6 minutes).
# `kafka-out` runs the PCE Kafka differential, FlowLink vs FlowPilot, against the test broker
#   (tests/kafka/broker.sh) and mock Integrations gateways. Local only: needs original/ and
#   re/e2e/flowlink_gateway_host (FlowLink's built-in gateway name, never printed); SKIPs without them.
# `kafka-pilot` runs FlowPilot alone in PCE Kafka mode (CI; no flowgen, no original/; about 6 minutes).
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
# The traffic generator is https://github.com/alexgoller/illumio-flowgen, checked out next to this repository.
FLOWGEN_SRC=${FLOWGEN_SRC:-$REPO/../illumio-flowgen}
IMAGE=rust:1-bookworm
OUT=$REPO/target/e2e
MODE=${1:-}

if [ "$MODE" = kafka-out ]; then
  [ -x "$REPO/original/usr/local/bin/flowlink" ] || { echo "SKIPPED: original/usr/local/bin/flowlink not present"; exit 0; }
  [ -s "$REPO/re/e2e/flowlink_gateway_host" ] || { echo "SKIPPED: re/e2e/flowlink_gateway_host not present"; exit 0; }
fi

FLOWGEN_BUILD='cd /src/flowgen && CARGO_TARGET_DIR=/src/flowpilot/target/flowgen-linux-amd64 cargo build --release --quiet --locked'
FLOWGEN_MOUNT=(-v "$FLOWGEN_SRC":/src/flowgen:ro)
if [ "$MODE" = kafka-pilot ]; then
  FLOWGEN_BUILD=true
  FLOWGEN_MOUNT=()
fi
docker run --rm --platform linux/amd64 \
  -v "$REPO":/src/flowpilot ${FLOWGEN_MOUNT[@]+"${FLOWGEN_MOUNT[@]}"} \
  -v flowlink-cargo-registry:/usr/local/cargo/registry \
  "$IMAGE" bash -c "
    set -e
    cd /src/flowpilot && CARGO_TARGET_DIR=target/linux-amd64 cargo build --release --quiet
    cd /src/flowpilot && CARGO_TARGET_DIR=target/linux-amd64 cargo build --release --quiet --example kafka_tool
    $FLOWGEN_BUILD"

if [ "$MODE" = kafka-out ] || [ "$MODE" = kafka-pilot ]; then
  BROKER=$REPO/tests/kafka/broker.sh
  trap '"$BROKER" down network' EXIT
  "$BROKER" up network
  for topic in flows-orig flows-pilot; do
    docker exec flowpilot-kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create \
      --topic "$topic" --partitions 3 --replication-factor 1 >/dev/null
  done
  BIN=/w/target/linux-amd64/release
  ARGS=(/w/target/kafka-certs "$BIN/examples/kafka_tool" "/w/target/e2e-$MODE" "$BIN/flowpilot")
  EXTRA=()
  if [ "$MODE" = kafka-out ]; then
    # The gateway name goes to the container through the environment (`-e NAME` copies it without
    # putting it in this script's output) and as a host mapping to the container's own mock gateway.
    FLOWLINK_GW=$(tr -d '[:space:]' <"$REPO/re/e2e/flowlink_gateway_host")
    export FLOWLINK_GW
    EXTRA=(-e FLOWLINK_GW --add-host "$FLOWLINK_GW:127.0.0.1")
    ARGS=(out "${ARGS[@]}" /w/original/usr/local/bin/flowlink /w/target/flowgen-linux-amd64/release/flowgen)
  else
    ARGS=(pilot "${ARGS[@]}")
  fi
  st=0
  docker run --rm --platform linux/amd64 --network flowpilot-e2e ${EXTRA[@]+"${EXTRA[@]}"} \
    -v "$REPO":/w:ro -v "$REPO/target":/w/target \
    "$IMAGE" bash /w/tests/e2e/kafka_out.sh "${ARGS[@]}" || st=$?
  echo "artifacts: $REPO/target/e2e-$MODE"
  exit $st
fi

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
