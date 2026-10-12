#!/usr/bin/env bash
set -euo pipefail

# Build and install nsproxy to /usr/local.
# Build options are forwarded to build-ui.sh.

case " $* " in
  *" --help "*|*" -h "*)
    ./build-ui.sh "$@"
    exit 0
    ;;
  *" --release "*)
    ./install_release.sh "$@"
    ;;
  *)
    ./build-ui.sh "$@"
    ./install_to_usr_local.sh
    ;;
esac
