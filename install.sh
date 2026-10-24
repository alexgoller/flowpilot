#!/bin/sh
# FlowPilot one-line installer: downloads a release binary, verifies its checksum, runs `flowpilot install`.
#   curl -fsSL https://github.com/alexgoller/flowpilot/releases/latest/download/install.sh | sh -s -- [install flags]
# Environment:
#   FLOWPILOT_VERSION            release to install, e.g. 0.9.0 or v0.9.0 (default: latest)
#   GITHUB_TOKEN                 optional GitHub token, e.g. to avoid the anonymous API rate limit
#   FLOWPILOT_RELEASE_BASE_URL   directory URL holding the release files (testing; skips GitHub entirely)
# Every argument is passed on to `flowpilot install`.
set -eu

REPO=alexgoller/flowpilot
API=https://api.github.com/repos/$REPO

die() {
  echo "install.sh: $*" >&2
  exit 1
}

# curl with the GitHub token. The header goes in through curl's config on stdin (printf is a builtin),
# so the token is never in the argv of any process.
curl_auth() {
  printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN" | curl -K - "$@"
}

# Download URL to FILE. Optional extra curl arguments follow. Never disables certificate checks.
download() {
  url=$1
  out=$2
  shift 2
  curl -fsSL "$@" -o "$out" "$url" || die "download failed: $url"
}

# Release JSON (stdout) for "latest" or a tag, with the token if there is one.
api_release() {
  if [ "$1" = latest ]; then path=releases/latest; else path=releases/tags/$1; fi
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl_auth -fsSL -H "Accept: application/vnd.github+json" "$API/$path"
  else
    curl -fsSL -H "Accept: application/vnd.github+json" "$API/$path"
  fi || die "cannot read release information from $API/$path (rate limited? set GITHUB_TOKEN)"
}

# Tag name from release JSON on stdin.
json_tag() {
  sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

# API asset id of the asset named $1, from release JSON on stdin. An asset object lists its
# "url" (.../releases/assets/<id>) before its "name".
json_asset_id() {
  tr ',' '\n' | awk -v want="\"name\":\"$1\"" '
    /\/releases\/assets\/[0-9]+"/ { id = $0; sub(/.*\/releases\/assets\//, "", id); sub(/".*/, "", id) }
    { line = $0; gsub(/[ \t]/, "", line); if (line ~ /"name":"/ && index(line, want) > 0 && id != "") { print id; exit } }'
}

# A new private directory under the first of $TMPDIR, /tmp, /var/tmp, $HOME where a file can be executed: CIS-hardened
# hosts mount /tmp noexec, and the downloaded binary has to run. Prints its path.
exec_tmpdir() {
  for parent in "${TMPDIR:-}" /tmp /var/tmp "${HOME:-}"; do
    [ -n "$parent" ] && [ -d "$parent" ] || continue
    d=$(mktemp -d "$parent/flowpilot.XXXXXX" 2>/dev/null) || continue
    printf '#!/bin/sh\nexit 0\n' >"$d/probe" && chmod 0755 "$d/probe" && "$d/probe" 2>/dev/null && {
      rm -f "$d/probe"
      echo "$d"
      return 0
    }
    rm -rf "$d"
  done
  return 1
}

# True when the install arguments read a secret from stdin (`--api-secret-file -`, `--api-key-file -`).
stdin_is_input() {
  prev=
  for a in "$@"; do
    case $prev:$a in
      --api-secret-file:- | --api-key-file:- | *:--api-secret-file=- | *:--api-key-file=-) return 0 ;;
    esac
    prev=$a
  done
  return 1
}

main() {
  case $(uname -s) in
    Linux) ;;
    *) die "FlowPilot runs on Linux only (found $(uname -s))" ;;
  esac
  case $(uname -m) in
    x86_64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "unsupported CPU architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
  esac
  command -v curl >/dev/null 2>&1 || command -v gh >/dev/null 2>&1 || die "curl or gh is required"

  tmp=$(exec_tmpdir) || die "no temporary directory that allows running programs (tried \$TMPDIR, /tmp, /var/tmp, \$HOME)"
  trap 'rm -rf "$tmp"' EXIT INT TERM HUP

  version=${FLOWPILOT_VERSION:-latest}
  version=${version#v}
  mode=anonymous
  if [ -n "${FLOWPILOT_RELEASE_BASE_URL:-}" ]; then
    mode=base
  elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    # gh only when it is logged in; otherwise the token or an anonymous download.
    mode=gh
  elif [ -n "${GITHUB_TOKEN:-}" ]; then
    mode=token
  fi
  [ "$mode" = gh ] || command -v curl >/dev/null 2>&1 || die "curl is required (or gh, logged in)"

  # Resolve "latest" to a concrete version; the asset names carry it.
  rel=
  if [ "$version" = latest ]; then
    case $mode in
      base) die "set FLOWPILOT_VERSION when FLOWPILOT_RELEASE_BASE_URL is used" ;;
      gh) tag=$(gh release view -R "$REPO" --json tagName -q .tagName) || die "cannot find the latest release (gh not logged in?)" ;;
      *) rel=$(api_release latest); tag=$(printf '%s\n' "$rel" | json_tag) ;;
    esac
    [ -n "$tag" ] || die "cannot determine the latest release"
    version=${tag#v}
  fi
  tag=v$version
  bin=flowpilot-$version-$arch-linux
  echo "Installing FlowPilot $version ($arch)"

  case $mode in
    base)
      base=${FLOWPILOT_RELEASE_BASE_URL%/}
      download "$base/$bin" "$tmp/$bin"
      download "$base/SHA256SUMS" "$tmp/SHA256SUMS"
      ;;
    gh)
      gh release download "$tag" -R "$REPO" -p "$bin" -p SHA256SUMS -D "$tmp" || die "gh release download failed for $tag"
      ;;
    token)
      [ -n "$rel" ] || rel=$(api_release "$tag")
      for f in "$bin" SHA256SUMS; do
        id=$(printf '%s\n' "$rel" | json_asset_id "$f")
        [ -n "$id" ] || die "release $tag has no asset $f"
        # With a token the asset is fetched through the API, asking for the raw bytes.
        curl_auth -fsSL -H "Accept: application/octet-stream" -o "$tmp/$f" "$API/releases/assets/$id" \
          || die "download failed: $API/releases/assets/$id"
      done
      ;;
    anonymous)
      base=https://github.com/$REPO/releases/download/$tag
      download "$base/$bin" "$tmp/$bin"
      download "$base/SHA256SUMS" "$tmp/SHA256SUMS"
      ;;
  esac

  # Verify only this binary's line of SHA256SUMS.
  grep " \**$bin\$" "$tmp/SHA256SUMS" >"$tmp/SHA256SUMS.bin" || die "SHA256SUMS has no entry for $bin"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c SHA256SUMS.bin >/dev/null 2>&1) || die "checksum mismatch for $bin; nothing was installed"
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmp" && shasum -a 256 -c SHA256SUMS.bin >/dev/null 2>&1) || die "checksum mismatch for $bin; nothing was installed"
  else
    die "sha256sum or shasum is required to verify the download"
  fi
  echo "Checksum OK"

  chmod 0755 "$tmp/$bin"
  if [ "$(id -u)" -eq 0 ]; then
    sudo=
  else
    command -v sudo >/dev/null 2>&1 || die "not running as root and sudo is not available"
    sudo=sudo
  fi
  # Under `curl | sh` stdin is the script pipe; give the wizard the terminal instead. Not when stdin is the secret.
  if ! stdin_is_input "$@" && [ ! -t 0 ] && (: </dev/tty) 2>/dev/null; then
    # shellcheck disable=SC2086
    $sudo "$tmp/$bin" install "$@" </dev/tty
  else
    # shellcheck disable=SC2086
    $sudo "$tmp/$bin" install "$@"
  fi
}

# Everything is parsed before main runs, so a truncated download executes nothing.
main "$@"
