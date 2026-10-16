#!/bin/sh
# Installs psion for this machine from the GitHub releases, after checking its SHA-256 checksum.
#   curl -fsSL https://raw.githubusercontent.com/Chandu00756/psionium/main/install.sh | sh
# Set PSION_VERSION=v1.0.0 to pin a version and PSION_INSTALL_DIR to choose where psion goes.
set -eu

releases="https://github.com/Chandu00756/psionium/releases"
version="${PSION_VERSION:-latest}"
dir="${PSION_INSTALL_DIR:-$HOME/.local/bin}"

fail() {
  echo "psion install: $*" >&2
  exit 1
}

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto-redir '=https' "$1" -o "$2"; }
  latest_url() { curl -fsSLI --proto-redir '=https' -o /dev/null -w '%{url_effective}' "$releases/latest"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
  latest_url() { wget -S --spider "$releases/latest" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n1 | tr -d '\r'; }
else
  fail "curl or wget is required"
fi

case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) fail "no build for $(uname -s); download one from $releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) fail "no build for $(uname -m) processors; download one from $releases" ;;
esac
# A shell running under Rosetta reports x86_64 on Apple silicon; install the native build.
if [ "$os" = apple-darwin ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
  arch=aarch64
fi
target="$arch-$os"

if [ "$version" = latest ]; then
  url=$(latest_url) || fail "could not reach $releases"
  version="${url##*/}"
fi
case "$version" in
  v[0-9]*) ;;
  *) fail "no release found at $releases" ;;
esac

name="psion-$version-$target"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $name.tar.gz"
fetch "$releases/download/$version/$name.tar.gz" "$tmp/$name.tar.gz" || fail "could not download $name.tar.gz"
fetch "$releases/download/$version/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download SHA256SUMS"

expected=$(grep " [*]\{0,1\}$name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch for $name.tar.gz; nothing installed"

tar xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$dir"
cp "$tmp/$name/psion" "$dir/psion.new"
chmod 0755 "$dir/psion.new"
mv -f "$dir/psion.new" "$dir/psion"
echo "Installed $("$dir/psion" --version) to $dir/psion"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to run psion from anywhere." ;;
esac
