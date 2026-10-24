#!/bin/sh
# install.sh with GITHUB_TOKEN must never put the token in any process argv: run it against a curl shim
# that records its argv and the config it reads from stdin, and check the token only appears in the latter.
# Usage: tests/install/token_not_in_argv.sh [path/to/install.sh]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script=${1:-$here/../../install.sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir "$t/bin" "$t/rel"
tok=SEKRET-TOKEN-123
case $(uname -m) in x86_64) arch=x86_64 ;; *) arch=aarch64 ;; esac
bin=flowpilot-9.9.9-$arch-linux
# shellcheck disable=SC2016
printf '#!/bin/sh\necho "FAKE-INSTALL: $*"\n' >"$t/rel/$bin"
(cd "$t/rel" && { sha256sum "$bin" 2>/dev/null || shasum -a 256 "$bin"; } >SHA256SUMS)
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo %s;; *) echo Linux;; esac\n' "$arch" >"$t/bin/uname"
# shellcheck disable=SC2016
printf '#!/bin/sh\nexec "$@"\n' >"$t/bin/sudo"
cat >"$t/bin/curl" <<SHIM
#!/bin/sh
echo "\$*" >>"$t/argv.log"
case " \$* " in *" -K - "*) cat >>"$t/stdin.log";; esac
out=; url=; prev=
for a in "\$@"; do [ "\$prev" = -o ] && out=\$a; prev=\$a; url=\$a; done
case \$url in
  */releases/latest) echo '{"tag_name":"v9.9.9","assets":[{"url":"https://x/releases/assets/11","id":11,"name":"SHA256SUMS"},{"url":"https://x/releases/assets/22","id":22,"name":"$bin"}]}';;
  */assets/11) cp "$t/rel/SHA256SUMS" "\$out";;
  */assets/22) cp "$t/rel/$bin" "\$out";;
esac
SHIM
# A gh that is not logged in (CI runners have a real one in /usr/bin): install.sh then takes the token path.
printf '#!/bin/sh\nexit 1\n' >"$t/bin/gh"
chmod +x "$t/bin/"*
# The shims first on PATH force the token path.
env -u FLOWPILOT_RELEASE_BASE_URL -u FLOWPILOT_VERSION PATH="$t/bin:/usr/bin:/bin" GITHUB_TOKEN=$tok \
  sh "$script" --yes >"$t/out.log" 2>&1 || { cat "$t/out.log"; echo "FAIL: install.sh failed"; exit 1; }
grep -q 'FAKE-INSTALL: install --yes' "$t/out.log" || { echo "FAIL: installer not run"; exit 1; }
if grep -q "$tok" "$t/argv.log"; then echo "FAIL: token in curl argv"; exit 1; fi
grep -q "Bearer $tok" "$t/stdin.log" || { echo "FAIL: token not sent via stdin config"; exit 1; }
echo "PASS: token only on curl's stdin config"
