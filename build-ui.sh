#!/usr/bin/env bash
set -euo pipefail

# Build nsproxy binaries with the serve console included by default.
# Usage: ./build-ui.sh [--no-web] [--release] [--help]

RELEASE=0
WEBUI=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-web)
      WEBUI=0
      ;;
    --release)
      RELEASE=1
      ;;
    -h|--help)
      echo "Usage: ./build-ui.sh [--no-web] [--release] [--help]"
      echo "  --no-web   Skip building and embedding the serve React console"
      echo "  --release  Build optimized binaries"
      echo "  --help     Show this help"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Use --help for usage." >&2
      exit 2
      ;;
  esac
  shift
done

# Packages and binaries
UI_PKG=nsproxy-ui
UI_BIN=nsproxy-ui
CLI_PKG=nsproxy-core
CLI_BIN=nsproxy

WEB_DIR="$(cd "$(dirname "$0")" && pwd)/crates/diag/web"
if [ $WEBUI -eq 1 ]; then
  if [ ! -d "$WEB_DIR/node_modules" ]; then
    echo "Installing serve web UI dependencies"
    npm --prefix "$WEB_DIR" ci
  fi
  echo "Building React serve web UI"
  npm --prefix "$WEB_DIR" run build
fi

build_cargo() {
  if [ $WEBUI -eq 1 ]; then
    NSPROXY_WEBUI=1 cargo build "$@"
  else
    NSPROXY_WEBUI=0 cargo build "$@"
  fi
}

if [ $RELEASE -eq 1 ]; then
  echo "Building release: cargo build -p $CLI_PKG --bin $CLI_BIN --release"
  build_cargo -p "$CLI_PKG" --bin "$CLI_BIN" --release
  echo "Building release: cargo build -p $UI_PKG --bin $UI_BIN --release"
  build_cargo -p "$UI_PKG" --bin "$UI_BIN" --release
  echo "Built: target/release/$CLI_BIN and target/release/$UI_BIN"
else
  echo "Building debug: cargo build -p $CLI_PKG --bin $CLI_BIN"
  build_cargo -p "$CLI_PKG" --bin "$CLI_BIN"
  echo "Building debug: cargo build -p $UI_PKG --bin $UI_BIN"
  build_cargo -p "$UI_PKG" --bin "$UI_BIN"
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
