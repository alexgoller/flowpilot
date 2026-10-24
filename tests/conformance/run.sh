#!/usr/bin/env bash
# Decoder conformance run: public vendor captures through FlowPilot and through tshark, compared.
#   tests/conformance/run.sh            fetch (if needed), build, decode both sides, compare
#   tests/conformance/run.sh --fp-only  reuse the tshark output, rerun FlowPilot and the comparison
# Output: target/conformance/report.md (and results.json). See tests/conformance/README.md.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$root/target/conformance"
docker="${DOCKER:-docker}"
image="flowpilot-conformance-tshark:trixie-20261005"
fp_only=""
[[ "${1:-}" == "--fp-only" ]] && fp_only="--fp-only"

mkdir -p "$work"
"$here/fetch_corpus.sh"
if [[ -z "$fp_only" ]]; then
  "$docker" build -q -t "$image" -f "$here/tshark.Dockerfile" "$here" >/dev/null
fi
(cd "$root" && cargo build --quiet --release --example pcap_decode)
python3 "$here/prepare.py" "$work/corpus" "$work"
DOCKER="$docker" python3 "$here/run_decoders.py" $fp_only "$work" "$root/target/release/examples/pcap_decode" "$image" >"$work/run_decoders.log"
python3 "$here/compare.py" "$work"
python3 "$here/selftest.py" "$work" >"$work/selftest.txt" || { cat "$work/selftest.txt"; echo "selftest: the comparison missed injected errors" >&2; exit 1; }
echo "selftest: every injected error detected (target/conformance/selftest.txt)"
