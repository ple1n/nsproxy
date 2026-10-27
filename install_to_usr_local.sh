#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")"

artifact_paths="$(
  cargo build \
    -p nsproxy-core --bin nsproxy --bin sproxy \
    -p nsproxy-ui --bin nsproxy-ui \
    --message-format=json |
    python3 -c 'import json, sys
executables = {}
for line in sys.stdin:
    message = json.loads(line)
    target = message.get("target", {})
    if (
        message.get("reason") == "compiler-artifact"
        and target.get("name") in {"nsproxy", "nsproxy-ui"}
        and "bin" in target.get("kind", [])
        and message.get("executable")
    ):
        executables[target["name"]] = message["executable"]
missing = {"nsproxy", "nsproxy-ui"} - executables.keys()
if missing:
    raise SystemExit("cargo did not report executables: " + ", ".join(sorted(missing)))
for name in ("nsproxy", "nsproxy-ui"):
    print(executables[name])'
)"
mapfile -t executable_paths <<< "$artifact_paths"
if [[ "$(dirname -- "${executable_paths[0]}")" != "$(dirname -- "${executable_paths[1]}")" ]]; then
  echo "nsproxy and nsproxy-ui were built into different directories" >&2
  exit 1
fi
binary_path="${executable_paths[0]}"

sudo "$binary_path" install /usr/local/bin/
"$binary_path" completions --fish
