#!/usr/bin/env bash
set -euo pipefail

ADDR="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"
SOCK="${ADDR#unix:path=}"

echo "user bus address: $ADDR"
echo "socket: $SOCK"

if [[ "$ADDR" != unix:path=* ]]; then
  echo "unsupported address format (expected unix:path=...)"
  exit 2
fi

ls -lh "$SOCK"
stat "$SOCK"

python3 - "$SOCK" <<'PY'
import socket, sys
p = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.5)
s.connect(p)
s.close()
print('connect_ok')
PY

if command -v busctl >/dev/null 2>&1; then
  timeout 4s busctl --address "$ADDR" call \
    org.freedesktop.DBus \
    /org/freedesktop/DBus \
    org.freedesktop.DBus \
    ListNames >/dev/null
  echo "busctl_roundtrip_ok"
else
  timeout 4s dbus-send \
    --bus="$ADDR" \
    --dest=org.freedesktop.DBus \
    --type=method_call \
    --print-reply \
    /org/freedesktop/DBus \
    org.freedesktop.DBus.ListNames >/dev/null
  echo "dbus_send_roundtrip_ok"
fi
