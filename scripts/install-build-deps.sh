#!/usr/bin/env bash
# Bootstrap the optional toolchain extras that .cargo/config.toml expects:
# - sccache (rustc-wrapper for cross-branch compile cache)
# - mold (Linux) / lld (macOS) for faster link times
#
# Run this once per workstation. CI installs the same tools via the
# `setup-sccache` and `setup-fast-linker` composite actions in .github/actions/.
#
# If a tool is already installed, the relevant package manager call is a
# no-op. Re-running is safe.

set -euo pipefail

os="$(uname -s)"
case "${os}" in
  Darwin)
    if ! command -v brew &> /dev/null; then
      echo "Homebrew not found. Install from https://brew.sh and re-run." >&2
      exit 1
    fi
    echo "Installing sccache + lld via Homebrew..."
    brew install sccache lld
    ;;
  Linux)
    if ! command -v apt-get &> /dev/null; then
      echo "This script targets apt-based Linux. Install sccache + mold + clang manually for your distro." >&2
      exit 1
    fi
    echo "Installing mold + clang via apt..."
    sudo apt-get update
    sudo apt-get install -y mold clang
    if ! command -v sccache &> /dev/null; then
      if command -v cargo &> /dev/null; then
        echo "Installing sccache via cargo..."
        cargo install sccache --locked
      else
        echo "cargo not on PATH; install Rust first (https://rustup.rs) then re-run." >&2
        exit 1
      fi
    fi
    ;;
  *)
    echo "Unsupported OS: ${os}" >&2
    exit 1
    ;;
esac

echo ""
echo "Done. Verify:"
command -v sccache > /dev/null && sccache --version
case "${os}" in
  Darwin) command -v ld64.lld > /dev/null && ld64.lld --version || true ;;
  Linux)  command -v mold > /dev/null && mold --version || true ;;
esac
echo ""
echo "Optional: set SCCACHE_DIR in your shell profile to relocate the cache,"
echo "  e.g. export SCCACHE_DIR=\"\$HOME/.cache/sccache\"  in ~/.zshrc or ~/.bashrc."
