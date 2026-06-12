#!/bin/sh
# Authio CLI installer.
#
#   curl -fsSL https://raw.githubusercontent.com/authio-com/authio_cli/main/scripts/install.sh | sh
#
# Detects your OS/arch, downloads the matching binary from the latest
# GitHub release, verifies its SHA-256 against the published checksums
# file, and installs it to /usr/local/bin (or ~/.local/bin when that is
# not writable).
#
# Overrides (env vars):
#   AUTHIO_REPO      GitHub repo            (default: authio-com/authio_cli)
#   AUTHIO_VERSION   release tag to install (default: latest)
#   AUTHIO_INSTALL_DIR  target directory    (default: auto-detected)
set -eu

REPO="${AUTHIO_REPO:-authio-com/authio_cli}"
BINARY="authio"

err() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '  %s\n' "$1"; }

need() { command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"; }
need uname
need tar
# curl or wget; pick whichever exists.
if command -v curl >/dev/null 2>&1; then
  DL="curl -fsSL"
  DLO="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
  DL="wget -qO-"
  DLO="wget -qO"
else
  err "need curl or wget"
fi

# ---- detect platform --------------------------------------------------
os="$(uname -s)"
case "$os" in
  Darwin) os="darwin" ;;
  Linux)  os="linux" ;;
  *) err "unsupported OS: $os (build from source: go install github.com/tcast/authio_cli/cmd/authio@latest)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

# ---- resolve version --------------------------------------------------
version="${AUTHIO_VERSION:-}"
if [ -z "$version" ]; then
  info "Resolving latest release..."
  version="$($DL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/')"
  [ -n "$version" ] || err "could not determine latest release (set AUTHIO_VERSION=vX.Y.Z)"
fi
# Numeric version (strip a leading v) used in asset filenames.
numver="$(printf '%s' "$version" | sed -E 's/^v//')"

archive="${BINARY}_${numver}_${os}_${arch}.tar.gz"
checksums="${BINARY}_${numver}_checksums.txt"
base="https://github.com/${REPO}/releases/download/${version}"

# ---- download ---------------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

info "Downloading ${archive} (${version})..."
$DLO "$tmp/$archive" "$base/$archive" || err "download failed: $base/$archive"
$DLO "$tmp/$checksums" "$base/$checksums" || err "download failed: $base/$checksums"

# ---- verify checksum --------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  sumcmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  sumcmd="shasum -a 256"
else
  err "need sha256sum or shasum to verify the download"
fi

expected="$(grep " ${archive}\$" "$tmp/$checksums" | awk '{print $1}' | head -n1)"
[ -n "$expected" ] || err "no checksum for ${archive} in ${checksums}"
actual="$(cd "$tmp" && $sumcmd "$archive" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
  err "checksum mismatch for ${archive} (expected ${expected}, got ${actual})"
fi
info "Checksum verified."

# ---- extract + install ------------------------------------------------
tar -xzf "$tmp/$archive" -C "$tmp"
[ -f "$tmp/$BINARY" ] || err "archive did not contain a '${BINARY}' binary"
chmod +x "$tmp/$BINARY"

# Choose an install dir we can write to.
dir="${AUTHIO_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    dir="/usr/local/bin"
  elif command -v sudo >/dev/null 2>&1 && [ -d /usr/local/bin ]; then
    dir="/usr/local/bin"
    SUDO="sudo"
  else
    dir="$HOME/.local/bin"
  fi
fi
mkdir -p "$dir" 2>/dev/null || true

if [ -n "${SUDO:-}" ]; then
  info "Installing to ${dir} (sudo)..."
  $SUDO mv "$tmp/$BINARY" "$dir/$BINARY"
else
  info "Installing to ${dir}..."
  mv "$tmp/$BINARY" "$dir/$BINARY"
fi

# ---- done -------------------------------------------------------------
printf '\n\033[32m✓\033[0m Installed %s %s to %s/%s\n\n' "$BINARY" "$version" "$dir" "$BINARY"
case ":$PATH:" in
  *":$dir:"*) ;;
  # shellcheck disable=SC2016  # $PATH must print literally for the user to copy.
  *) printf '  Add %s to your PATH:\n    export PATH="%s:$PATH"\n\n' "$dir" "$dir" ;;
esac
"$dir/$BINARY" version || true
