#!/usr/bin/env bash
# Test Kafka broker for the PCE Kafka tests: apache/kafka 3.9.2, KRaft single node, topic `flowpilot`
# with 3 partitions.
# Usage: tests/kafka/broker.sh up|down [host|network]
#   host     (default) advertises localhost:909x, ports published on the host (for `cargo test`)
#   network  advertises kafka:909x on the Docker network flowpilot-e2e (alias `kafka`), no host ports
# Listeners: 9092 PLAINTEXT | 9093 SASL_SSL PLAIN, user $ConnectionString | 9094 SSL, client cert required.
# Every `up` generates fresh certificates and a fresh connection string into target/kafka-certs/:
#   ca.pem, server.pem/server.key, client.pem/client.key (SANs localhost and kafka), connection_string.
# Secret files (keys, connection string, broker config) are mode 0600. The broker runs as root in the
# container so it can read them whatever the host uid.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=apache/kafka:3.9.2
NAME=flowpilot-kafka
NETWORK=flowpilot-e2e
TOPIC=flowpilot
CERTS=$REPO/target/kafka-certs

usage() { echo "usage: $0 up|down [host|network]" >&2; exit 2; }

gen_certs() {
  rm -rf "$CERTS"
  mkdir -p "$CERTS/config"
  chmod 700 "$CERTS"
  umask 077
  local d=$CERTS
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$d/ca.ext"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/ca.key" 2>/dev/null
  openssl req -new -key "$d/ca.key" -subj /CN=flowpilot-test-ca -out "$d/ca.csr"
  openssl x509 -req -in "$d/ca.csr" -signkey "$d/ca.key" -days 30 -extfile "$d/ca.ext" -out "$d/ca.pem" 2>/dev/null
  local who
  for who in server client; do
    local eku=serverAuth
    [ "$who" = client ] && eku=clientAuth
    printf 'subjectAltName=DNS:localhost,DNS:kafka\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n' \
      "$eku" >"$d/$who.ext"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/$who.key" 2>/dev/null
    openssl req -new -key "$d/$who.key" -subj "/CN=flowpilot-test-$who" -out "$d/$who.csr"
    openssl x509 -req -in "$d/$who.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial -days 30 \
      -extfile "$d/$who.ext" -out "$d/$who.pem" 2>/dev/null
    cat "$d/$who.key" "$d/$who.pem" >"$d/$who-keystore.pem"
  done
  rm -f "$d"/*.csr "$d"/*.ext "$d"/*.srl
  printf 'Endpoint=sb://flowpilot-test.invalid/;SharedAccessKeyName=test;SharedAccessKey=%s' \
    "$(openssl rand -hex 24)" >"$d/connection_string"
  chmod 644 "$d/ca.pem" "$d/server.pem" "$d/client.pem"
  chmod 600 "$d"/*.key "$d"/*-keystore.pem "$d/connection_string"
}

write_config() {
  local adv=$1 cs
  cs=$(cat "$CERTS/connection_string")
  umask 077
  cat >"$CERTS/config/server.properties" <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:29093
listeners=PLAINTEXT://:9092,SASL_SSL://:9093,SSL://:9094,CONTROLLER://:29093
advertised.listeners=PLAINTEXT://$adv:9092,SASL_SSL://$adv:9093,SSL://$adv:9094
listener.security.protocol.map=PLAINTEXT:PLAINTEXT,SASL_SSL:SASL_SSL,SSL:SSL,CONTROLLER:PLAINTEXT
controller.listener.names=CONTROLLER
inter.broker.listener.name=PLAINTEXT
log.dirs=/tmp/kraft-combined-logs
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
auto.create.topics.enable=false
ssl.keystore.type=PEM
ssl.keystore.location=/certs/server-keystore.pem
ssl.truststore.type=PEM
ssl.truststore.location=/certs/ca.pem
ssl.endpoint.identification.algorithm=
listener.name.ssl.ssl.client.auth=required
sasl.enabled.mechanisms=PLAIN
listener.name.sasl_ssl.sasl.enabled.mechanisms=PLAIN
listener.name.sasl_ssl.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required user_\$ConnectionString="$cs";
EOF
  chmod 600 "$CERTS/config/server.properties"
}

up() {
  local mode=$1 adv net=()
  case $mode in
    host) adv=localhost; net=(-p 9092:9092 -p 9093:9093 -p 9094:9094) ;;
    network)
      adv=kafka
      docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null
      net=(--network "$NETWORK" --network-alias kafka --hostname kafka) ;;
    *) usage ;;
  esac
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  gen_certs
  write_config "$adv"
  docker run -d --name "$NAME" --user root "${net[@]}" \
    -e CLUSTER_ID=flowpilot-test-kafka-01 \
    -v "$CERTS/config":/mnt/shared/config:ro -v "$CERTS":/certs:ro \
    "$IMAGE" >/dev/null
  local i
  for i in $(seq 1 60); do
    if docker exec "$NAME" /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; then
      docker exec "$NAME" /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create \
        --if-not-exists --topic "$TOPIC" --partitions 3 --replication-factor 1 >/dev/null
      echo "kafka up ($mode): $adv:9092 PLAINTEXT, $adv:9093 SASL_SSL, $adv:9094 SSL; topic $TOPIC; certs in $CERTS"
      return 0
    fi
    sleep 1
  done
  echo "kafka did not come up; last log lines:" >&2
  docker logs --tail 30 "$NAME" >&2 || true
  exit 1
}

down() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ "${1:-host}" = network ]; then
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
  fi
  echo "kafka down"
}

case ${1:-} in
  up) up "${2:-host}" ;;
  down) down "${2:-host}" ;;
  *) usage ;;
esac
