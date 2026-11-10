#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")"

script_dir="$(pwd)"
"$script_dir/build-ui.sh" "$@"

build_profile=debug
for arg in "$@"; do
  if [[ "$arg" == "--release" ]]; then
    build_profile=release
    break
  fi
done

target_dir="$(
  cargo metadata --format-version=1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
)"
binary_path="$target_dir/$build_profile/nsproxy"

sudo "$binary_path" install /usr/local/bin/
"$binary_path" completions --fish
