#!/usr/bin/env bash
# Installer checks on a real systemd host: a Rocky Linux VM run with Lima, SELinux enforcing (see docs/testing.md).
# Creates the VM on first use (later runs reuse it), copies in the static binary from tools/build-static.sh, starts two
# mock PCEs on this Mac (one normal, one answering every API call with 401), reachable from the VM as
# host.lima.internal, and runs tests/vm/checks.sh inside the VM as root.
# Usage: tests/vm/run.sh rocky9|rocky8|rocky9-x86        CHECKS=basic: install, status and uninstall only
# Remove a VM with: limactl delete -f flowpilot-rocky9
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
PORT=${VM_PCE_PORT:-18443}
PORT401=$((PORT + 1))
EXTRA=()
case ${1:-} in
  rocky9) VM=flowpilot-rocky9 TEMPLATE=rocky-9 ARCH=aarch64 ;;
  # Rocky 8's aarch64 kernel uses 64 KB pages, which Apple silicon does not support: x86_64 under emulation instead.
  rocky8) VM=flowpilot-rocky8 TEMPLATE=rocky-8 ARCH=x86_64 EXTRA=(--arch=x86_64 --vm-type=qemu) ;;
  rocky9-x86) VM=flowpilot-rocky9-x86 TEMPLATE=rocky-9 ARCH=x86_64 EXTRA=(--arch=x86_64 --vm-type=qemu) ;;
  *) echo "usage: $0 rocky9|rocky8|rocky9-x86   (CHECKS=basic for the install, status and uninstall subset)" >&2; exit 2 ;;
esac
if ! command -v limactl >/dev/null; then
  echo "limactl not found; install Lima with: brew install lima" >&2
  exit 2
fi
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/Cargo.toml" | head -1)
BIN=$REPO/dist/flowpilot-$VERSION-$ARCH-linux
[ -f "$BIN" ] || { echo "$BIN is missing; build it with tools/build-static.sh" >&2; exit 2; }
OUT=$REPO/target/vm/$1
rm -rf "$OUT" && mkdir -p "$OUT"

# A CA and a leaf for host.lima.internal signed by it (rustls refuses a CA certificate as the server's own).
cat > "$OUT/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
[dn]
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:host.lima.internal
authorityKeyIdentifier = keyid
EOF
(
  cd "$OUT"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/CN=FlowPilot VM test CA" \
    -config ca.cnf -extensions ca 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout key.pem -out leaf.csr -subj /CN=host.lima.internal -config ca.cnf 2>/dev/null
  openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem -days 2 \
    -extfile ca.cnf -extensions leaf 2>/dev/null
)

# A canned NetFlow v5 datagram: one TCP flow 10.1.1.10:51000 -> 10.1.2.10:443, stamped now.
python3 - "$OUT/netflow-v5.bin" <<'PY'
import struct, sys, time
header = struct.pack("!HHIIIIBBH", 5, 1, 600000, int(time.time()), 0, 1, 0, 0, 0)
record = struct.pack("!IIIHHIIIIHHBBBBHHBBH", 0x0A01010A, 0x0A01020A, 0, 0, 0, 10, 4200, 599000, 599900,
                     51000, 443, 0, 0x18, 6, 0, 0, 0, 24, 24, 0)
open(sys.argv[1], "wb").write(header + record)
PY

python3 "$REPO/tests/e2e/mock_pce.py" "$PORT" "$OUT/posts" "$OUT/cert.pem" "$OUT/key.pem" 2>"$OUT/pce.log" &
MOCK=$!
python3 "$REPO/tests/e2e/mock_pce.py" "$PORT401" "$OUT/posts401" "$OUT/cert.pem" "$OUT/key.pem" --api-status 401 \
  2>"$OUT/pce401.log" &
MOCK401=$!
trap 'kill $MOCK $MOCK401 2>/dev/null || true' EXIT
for p in "$PORT" "$PORT401"; do
  for _ in $(seq 50); do nc -z 127.0.0.1 "$p" >/dev/null 2>&1 && break; sleep 0.1; done
  nc -z 127.0.0.1 "$p" >/dev/null 2>&1 || { echo "mock PCE on port $p did not start; see $OUT/pce*.log" >&2; exit 1; }
done

if ! limactl list -q 2>/dev/null | grep -qx "$VM"; then
  limactl start --name="$VM" --mount-none --containerd=none --tty=false ${EXTRA[@]+"${EXTRA[@]}"} "template:$TEMPLATE"
elif [ "$(limactl list --format '{{.Status}}' "$VM")" != Running ]; then
  limactl start --tty=false "$VM"
fi
vm() { limactl shell --workdir / "$VM" "$@"; }
vm rm -rf /tmp/fpvm
vm mkdir -p /tmp/fpvm
for f in "$BIN:flowpilot" "$REPO/tests/vm/checks.sh:checks.sh" "$OUT/ca.pem:ca.pem" "$OUT/netflow-v5.bin:netflow-v5.bin"; do
  limactl copy "${f%%:*}" "$VM:/tmp/fpvm/${f##*:}"
done
vm chmod 755 /tmp/fpvm/flowpilot
vm sudo CHECKS="${CHECKS:-full}" bash /tmp/fpvm/checks.sh "$PORT" "$PORT401" | tee "$OUT/checks.log"
limactl copy "$VM:/tmp/fpvm/transcript" "$OUT/transcript" || true
echo "artifacts: $OUT"
tail -1 "$OUT/checks.log" | grep -qx "RESULT: PASS"
