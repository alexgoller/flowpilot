#!/bin/sh
# Run one fuzz target inside the flowpilot-fuzz container (see fuzz/README.md).
#   fuzz/run.sh <target> [seconds=600] [jobs=2] [extra cargo-fuzz flags, e.g. -O]
# Corpus: fuzz/corpus/<target> (+ read-only seeds), crashes: fuzz/artifacts/<target>/,
# log: fuzz/logs/<target>.log. Fork mode keeps going after a crash/timeout/OOM, so one
# finding does not hide the next; every artifact is still written.
set -eu
t=$1
secs=${2:-600}
jobs=${3:-2}
shift $(( $# < 3 ? $# : 3 ))
cd "$(dirname "$0")/.."
mkdir -p "fuzz/corpus/$t" "fuzz/artifacts/$t" fuzz/logs
exec cargo fuzz run --target-dir "${FUZZ_TARGET_DIR:-/target}" "$@" "$t" "fuzz/corpus/$t" "fuzz/seeds/$t" -- \
  -max_total_time="$secs" -fork="$jobs" -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
  -rss_limit_mb=1024 -malloc_limit_mb=512 -timeout=10 -max_len=8192 -print_final_stats=1 \
  >"fuzz/logs/$t.log" 2>&1
