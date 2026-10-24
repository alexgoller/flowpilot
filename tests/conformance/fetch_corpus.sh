#!/usr/bin/env bash
# Downloads the conformance corpus listed in corpus.lock into target/conformance/corpus/.
# Every file is pinned to a commit and checked against its SHA-256; files already present with the
# right hash are not downloaded again. The corpus is third-party data (licences in SOURCES.md) and
# lives under target/, which is not committed.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
dest="${CORPUS_DIR:-$root/target/conformance/corpus}"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetched=0 kept=0 failed=0
while read -r source repo commit path hash; do
  case "$source" in ''|'#'*) continue ;; esac
  out="$dest/$source/$path"
  if [[ -f "$out" && "$(sha256 "$out")" == "$hash" ]]; then
    kept=$((kept + 1))
    continue
  fi
  mkdir -p "$(dirname "$out")"
  url="https://raw.githubusercontent.com/$repo/$commit/$path"
  if ! curl -fsSL --retry 3 -o "$out.tmp" "$url"; then
    echo "download failed: $url" >&2
    failed=$((failed + 1))
    continue
  fi
  got="$(sha256 "$out.tmp")"
  if [[ "$got" != "$hash" ]]; then
    echo "hash mismatch: $url (got $got)" >&2
    rm -f "$out.tmp"
    failed=$((failed + 1))
    continue
  fi
  mv "$out.tmp" "$out"
  fetched=$((fetched + 1))
done < "$here/corpus.lock"

echo "corpus: $fetched fetched, $kept already present, $failed failed -> $dest"
[[ $failed -eq 0 ]]
