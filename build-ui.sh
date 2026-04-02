#!/usr/bin/env bash
set -euo pipefail

# Build the UI and nsproxy CLI binaries (debug by default).
# Usage: ./build-ui.sh [--release]

RELEASE=0
if [ "${1-}" = "--release" ]; then
  RELEASE=1
fi

# Packages and binaries
UI_PKG=nsproxy-ui
UI_BIN=nsproxy-ui
CLI_PKG=nsproxy-core
CLI_BIN=nsproxy

if [ $RELEASE -eq 1 ]; then
  echo "Building release: cargo build -p $CLI_PKG --bin $CLI_BIN --release"
  cargo build -p "$CLI_PKG" --bin "$CLI_BIN" --release
  echo "Building release: cargo build -p $UI_PKG --bin $UI_BIN --release"
  cargo build -p "$UI_PKG" --bin "$UI_BIN" --release
  echo "Built: target/release/$CLI_BIN and target/release/$UI_BIN"
else
  echo "Building debug: cargo build -p $CLI_PKG --bin $CLI_BIN"
  cargo build -p "$CLI_PKG" --bin "$CLI_BIN"
  echo "Building debug: cargo build -p $UI_PKG --bin $UI_BIN"
  cargo build -p "$UI_PKG" --bin "$UI_BIN"
  echo "Built: target/debug/$CLI_BIN and target/debug/$UI_BIN"
fi

# Helpful run hints
if [ $RELEASE -eq 1 ]; then
  echo "Run CLI: ./target/release/$CLI_BIN"
  echo "Run UI:  ./target/release/$UI_BIN"
else
  echo "Run CLI: ./target/debug/$CLI_BIN"
  echo "Run UI:  ./target/debug/$UI_BIN"
fi
