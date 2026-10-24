#!/bin/sh
# install.sh download and hand-over paths, against curl, gh and uname shims (no network):
#   - gh installed but not logged in falls back to GITHUB_TOKEN, or to an anonymous download;
#   - an unusable $TMPDIR falls back to the next directory;
#   - `--api-secret-file -` keeps stdin (the secret) for the installer instead of the terminal.
# Usage: tests/install/install_sh_paths.sh [path/to/install.sh]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script=${1:-$here/../../install.sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir "$t/bin" "$t/rel"
case $(uname -m) in x86_64) arch=x86_64 ;; *) arch=aarch64 ;; esac
bin=flowpilot-9.9.9-$arch-linux
# The fake release binary shows its arguments and what it reads on stdin.
# shellcheck disable=SC2016
printf '#!/bin/sh\necho "FAKE-INSTALL: $*"\n[ -t 0 ] || echo "STDIN: $(cat)"\n' >"$t/rel/$bin"
(cd "$t/rel" && { sha256sum "$bin" 2>/dev/null || shasum -a 256 "$bin"; } >SHA256SUMS)
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo %s;; *) echo Linux;; esac\n' "$arch" >"$t/bin/uname"
# shellcheck disable=SC2016
printf '#!/bin/sh\nexec "$@"\n' >"$t/bin/sudo"
# gh is installed but not logged in: `gh auth status` fails, anything else is recorded as a failure.
cat >"$t/bin/gh" <<SHIM
#!/bin/sh
[ "\$1 \$2" = "auth status" ] && exit 1
echo "gh \$*" >>"$t/gh.log"
exit 1
SHIM
cat >"$t/bin/curl" <<SHIM
#!/bin/sh
echo "\$*" >>"$t/argv.log"
case " \$* " in *" -K - "*) cat >/dev/null;; esac
out=; url=; prev=
for a in "\$@"; do [ "\$prev" = -o ] && out=\$a; prev=\$a; url=\$a; done
case \$url in
  */releases/latest) echo '{"tag_name":"v9.9.9","assets":[{"url":"https://x/releases/assets/11","id":11,"name":"SHA256SUMS"},{"url":"https://x/releases/assets/22","id":22,"name":"$bin"}]}';;
  */assets/11 | */releases/download/v9.9.9/SHA256SUMS) cp "$t/rel/SHA256SUMS" "\$out";;
  */assets/22 | */releases/download/v9.9.9/$bin) cp "$t/rel/$bin" "\$out";;
  *) exit 22;;
esac
SHIM
chmod +x "$t/bin/"*

fail() {
  echo "FAIL: $*"
  cat "$t/out.log"
  exit 1
}

# Runs install.sh with the shims first on PATH; extra variables as arguments before `--`.
run() {
  : >"$t/argv.log"
  vars=
  while [ "$1" != -- ]; do vars="$vars $1"; shift; done
  shift
  # shellcheck disable=SC2086
  env -u FLOWPILOT_RELEASE_BASE_URL -u FLOWPILOT_VERSION -u GITHUB_TOKEN PATH="$t/bin:/usr/bin:/bin" $vars \
    sh "$script" "$@" >"$t/out.log" 2>&1 </dev/null || fail "install.sh failed"
}

# gh not logged in, a token: the token path.
run GITHUB_TOKEN=tok -- --yes
grep -q 'FAKE-INSTALL: install --yes' "$t/out.log" || fail "installer not run (token)"
grep -q '/releases/assets/22' "$t/argv.log" || fail "token path not used"
[ ! -s "$t/gh.log" ] || fail "gh used although not logged in: $(cat "$t/gh.log")"

# gh not logged in, no token, and a $TMPDIR that does not exist: anonymous, from the next directory.
run TMPDIR="$t/missing" -- --yes
grep -q 'FAKE-INSTALL: install --yes' "$t/out.log" || fail "installer not run (anonymous)"
grep -q '/releases/download/v9.9.9/' "$t/argv.log" || fail "anonymous path not used"

# The secret on stdin reaches the installer.
: >"$t/argv.log"
printf 'the-secret\n' | env -u FLOWPILOT_RELEASE_BASE_URL -u FLOWPILOT_VERSION -u GITHUB_TOKEN PATH="$t/bin:/usr/bin:/bin" \
  sh "$script" --yes --api-secret-file - >"$t/out.log" 2>&1 || fail "install.sh failed (stdin secret)"
grep -q 'STDIN: the-secret' "$t/out.log" || fail "the secret on stdin did not reach the installer"

# The terminal is only taken over when stdin is not the secret (checked on the function: a test has no terminal).
eval "$(sed -n '/^stdin_is_input() {/,/^}/p' "$script")"
stdin_is_input --yes --api-secret-file - || fail "stdin_is_input: --api-secret-file -"
stdin_is_input --api-key-file=- || fail "stdin_is_input: --api-key-file=-"
! stdin_is_input --yes --api-secret-file /root/secret || fail "stdin_is_input: a file"
! stdin_is_input --pce - || fail "stdin_is_input: another flag"
echo "PASS: gh fallback, temporary directory fallback, secret on stdin"
