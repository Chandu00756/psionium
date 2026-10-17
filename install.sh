#!/bin/sh
# Installs psion for this machine from the GitHub releases, after checking its SHA-256 checksum.
# Works on macOS, Linux, and Windows in Git Bash, MSYS2 or Cygwin. Run it again to update.
#   curl -fsSL https://raw.githubusercontent.com/Chandu00756/psionium/main/install.sh | sh
# Set PSION_VERSION=v1.1.0 to pin a version and PSION_INSTALL_DIR to choose where psion goes.
set -eu

releases="https://github.com/Chandu00756/psionium/releases"
version="${PSION_VERSION:-latest}"

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

# Archive type, program name and default folder; Git Bash puts ~/bin on PATH.
ext=tar.gz
exe=psion
default_dir="$HOME/.local/bin"
case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  MINGW* | MSYS* | CYGWIN*)
    os=pc-windows-msvc
    ext=zip
    exe=psion.exe
    default_dir="$HOME/bin"
    ;;
  *) fail "no build for $(uname -s); download one from $releases" ;;
esac
dir="${PSION_INSTALL_DIR:-$default_dir}"
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) fail "no build for $(uname -m) processors; download one from $releases" ;;
esac
# Windows has an x86-64 build only; Windows on ARM runs it under emulation.
if [ "$os" = pc-windows-msvc ]; then
  arch=x86_64
fi
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

archive="$name.$ext"
echo "Downloading $archive"
fetch "$releases/download/$version/$archive" "$tmp/$archive" || fail "could not download $archive"
fetch "$releases/download/$version/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download SHA256SUMS"

expected=$(grep " [*]\{0,1\}$archive\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch for $archive; nothing installed"

if [ "$ext" = zip ]; then
  if command -v unzip >/dev/null 2>&1; then
    unzip -q "$tmp/$archive" -d "$tmp" || fail "could not unpack $archive"
  elif command -v powershell.exe >/dev/null 2>&1 && command -v cygpath >/dev/null 2>&1; then
    powershell.exe -NoProfile -NonInteractive -Command \
      "Expand-Archive -LiteralPath '$(cygpath -w "$tmp/$archive")' -DestinationPath '$(cygpath -w "$tmp")'" \
      || fail "could not unpack $archive"
  else
    fail "unzip or PowerShell is needed to unpack $archive"
  fi
else
  tar xzf "$tmp/$archive" -C "$tmp"
fi
[ -f "$tmp/$name/$exe" ] || fail "$archive does not contain $exe"
mkdir -p "$dir"
cp "$tmp/$name/$exe" "$dir/$exe.new"
chmod 0755 "$dir/$exe.new"
mv -f "$dir/$exe.new" "$dir/$exe" || fail "could not replace $dir/$exe; close any running psion and try again"
echo "Installed $("$dir/$exe" --version) to $dir/$exe"
case ":$PATH:" in
  *":$dir:"*) ;;
  *)
    echo "Add $dir to your PATH to run psion from anywhere."
    if [ "$os" = pc-windows-msvc ]; then
      echo "In Git Bash, open a new window, or run: export PATH=\"$dir:\$PATH\""
    fi
    ;;
esac
