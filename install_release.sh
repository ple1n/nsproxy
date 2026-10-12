#!/usr/bin/env bash
set -euo pipefail

case " $* " in
  *" --help "*|*" -h "*)
    ./build-ui.sh --release "$@"
    exit 0
    ;;
esac

./build-ui.sh --release "$@"
sudo ./target/release/nsproxy install /usr/local/bin/