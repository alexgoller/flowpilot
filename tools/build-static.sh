#!/usr/bin/env bash
# Build static musl binaries for x86_64 and aarch64 Linux in Docker (works on a Mac or any Docker host).
# Output: dist/flowpilot-<version>-<arch>-linux and dist/SHA256SUMS
# Usage: tools/build-static.sh
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=rust:1.97.1-bookworm
ZIG_VERSION=0.14.1
# SHA-256 of zig-<arch>-linux-0.14.1.tar.xz, from https://ziglang.org/download/index.json. Change with ZIG_VERSION.
ZIG_SHA256_X86_64=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c
ZIG_SHA256_AARCH64=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b
ZIGBUILD_VERSION=0.19.8
TARGETS="x86_64 aarch64"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/Cargo.toml" | head -1)
mkdir -p "$REPO/dist"

# Native-arch container (no emulation): zig cross-compiles both targets. Zig and cargo-zigbuild are cached in a volume.
docker run --rm \
  -v "$REPO":/src -w /src \
  -v flowpilot-cargo-registry:/usr/local/cargo/registry \
  -v flowpilot-build-tools:/opt/tools \
  -e ZIG_VERSION=$ZIG_VERSION -e ZIG_SHA256_X86_64=$ZIG_SHA256_X86_64 -e ZIG_SHA256_AARCH64=$ZIG_SHA256_AARCH64 \
  -e ZIGBUILD_VERSION=$ZIGBUILD_VERSION -e TARGETS="$TARGETS" -e VERSION=$VERSION \
  "$IMAGE" bash -c '
    set -euo pipefail
    export PATH=/opt/tools/zig:/opt/tools/bin:$PATH
    if [ ! -x /opt/tools/zig/zig ] || [ "$(zig version)" != "$ZIG_VERSION" ]; then
      rm -rf /opt/tools/zig
      mkdir -p /opt/tools/zig
      case $(uname -m) in
        x86_64) want=$ZIG_SHA256_X86_64 ;;
        aarch64) want=$ZIG_SHA256_AARCH64 ;;
        *) echo "no zig checksum for $(uname -m)" >&2; exit 1 ;;
      esac
      tarball=/tmp/zig.tar.xz
      curl -fsSL -o "$tarball" "https://ziglang.org/download/$ZIG_VERSION/zig-$(uname -m)-linux-$ZIG_VERSION.tar.xz"
      echo "$want  $tarball" | sha256sum -c - || { echo "zig download does not match its pinned SHA-256" >&2; exit 1; }
      tar -xJf "$tarball" -C /opt/tools/zig --strip-components=1
      rm -f "$tarball"
    fi
    if ! cargo-zigbuild --version 2>/dev/null | grep -q "$ZIGBUILD_VERSION"; then
      cargo install --locked --root /opt/tools --version "$ZIGBUILD_VERSION" cargo-zigbuild
    fi
    for arch in $TARGETS; do
      rustup target add $arch-unknown-linux-musl
      CARGO_TARGET_DIR=target/static cargo zigbuild --release --locked --target $arch-unknown-linux-musl
      cp target/static/$arch-unknown-linux-musl/release/flowpilot dist/flowpilot-$VERSION-$arch-linux
    done
    cd dist && sha256sum flowpilot-$VERSION-*-linux > SHA256SUMS'
echo "built: $REPO/dist"
cat "$REPO/dist/SHA256SUMS"
