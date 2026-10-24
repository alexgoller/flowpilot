#!/bin/sh
# Group crash artifacts by panic site and message (run inside the flowpilot-fuzz container):
#   fuzz/triage.sh [target...]     (default: every target with artifacts)
# TRIAGE_DIR=dir reads artifacts from dir instead of fuzz/artifacts. Set
# FLOWPILOT_FUZZ_LOG_ORACLE=off to look for crashes other than finding F1.
# TRIAGE_SAMPLE=N checks a random sample of N artifacts per target (default 40; 0 = all).
# Prints "<count> <target> <panic location> <message, digits as N>" and one example file per
# group. Panics raised by the harness oracles point at fuzz/src/lib.rs.
cd "$(dirname "$0")/.."
bin=${FUZZ_TARGET_DIR:-/target}/aarch64-unknown-linux-gnu/release
[ -d "$bin" ] || bin=${FUZZ_TARGET_DIR:-/target}/x86_64-unknown-linux-gnu/release
adir=${TRIAGE_DIR:-fuzz/artifacts}
targets=${*:-$(ls "$adir")}
for t in $targets; do
  files=$(ls "$adir/$t" 2>/dev/null | sed "s|^|$adir/$t/|")
  [ "${TRIAGE_SAMPLE:-40}" = 0 ] || files=$(printf "%s\n" $files | shuf -n "${TRIAGE_SAMPLE:-40}")
  for f in $files; do
    [ -f "$f" ] || continue
    out=$(env -u FLOWPILOT_FUZZ_VERBOSE "$bin/$t" -runs=1 -timeout=20 "$f" 2>&1 | grep -v "^[0-9]\{4\}-")
    loc=$(printf '%s\n' "$out" | grep -m1 "panicked at" | sed -E 's/.*panicked at //; s/:$//')
    msg=$(printf '%s\n' "$out" | grep -m1 -A1 "panicked at" | tail -1 | sed -E 's/[0-9]+/N/g' | cut -c1-120)
    [ -n "$loc" ] || { loc=$(printf '%s\n' "$out" | grep -m1 -E "ERROR: libFuzzer|SUMMARY" | cut -c1-80); msg=""; }
    printf '%s\t%s\t%s\t%s\n' "$t" "$loc" "$msg" "$f"
  done
done | sort | awk -F'\t' '{k=$1"\t"$2"\t"$3; n[k]++; if (!(k in ex)) ex[k]=$4} END {for (k in n) print n[k]"\t"k"\t"ex[k]}' | sort -k2
