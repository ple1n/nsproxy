#!/usr/bin/env bash
# Diagnose the session D-Bus visible to the current process.
#
# Run this *inside* a freshly started container so the commands use the same
# namespaces as the application being diagnosed:
#   bash devscripts/diag_dbus_container.sh
#
# Optional first argument is only shown in the report as the expected profile.

set -u -o pipefail

PROFILE="${1:-${NSP_PROFILE:-unknown}}"
ADDR="${DBUS_SESSION_BUS_ADDRESS:-}"
TIMEOUT_SECONDS="${DBUS_DIAG_TIMEOUT_SECONDS:-5}"

section() {
    printf '\n=== %s ===\n' "$1"
}

run() {
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
    "$@"
    local status=$?
    printf '[exit=%d]\n' "$status"
    return 0
}

section "Context"
printf 'profile: %s\n' "$PROFILE"
printf 'uid/gid: '
id
printf 'pid: %s\n' "$$"
printf 'DBUS_SESSION_BUS_ADDRESS: %s\n' "${ADDR:-<unset>}"
printf 'XDG_RUNTIME_DIR: %s\n' "${XDG_RUNTIME_DIR:-<unset>}"
printf 'XDG_CURRENT_DESKTOP: %s\n' "${XDG_CURRENT_DESKTOP:-<unset>}"
printf 'mount namespace: '
readlink /proc/self/ns/mnt 2>/dev/null || true
printf 'network namespace: '
readlink /proc/self/ns/net 2>/dev/null || true
printf 'pid namespace: '
readlink /proc/self/ns/pid 2>/dev/null || true

if [[ -z "$ADDR" ]]; then
    section "Result"
    echo "FAIL: DBUS_SESSION_BUS_ADDRESS is unset. This process has no session bus."
    exit 2
fi

if [[ "$ADDR" != unix:path=* ]]; then
    section "Address"
    echo "Address is not a unix:path address; direct socket inspection is skipped."
else
    SOCK_PATH="${ADDR#unix:path=}"
    SOCK_PATH="${SOCK_PATH%%,*}"

    section "Socket"
    printf 'socket path: %s\n' "$SOCK_PATH"
    run ls -l "$SOCK_PATH"
    run stat -c 'type=%F mode=%a owner=%U:%G inode=%i path=%n' "$SOCK_PATH"

    if [[ ! -S "$SOCK_PATH" ]]; then
        section "Result"
        echo "FAIL: the configured session-bus socket does not exist in this namespace."
        exit 3
    fi
fi

section "D-Bus daemon processes visible here"
ps -eo pid,ppid,pgid,user,stat,args \
    | grep -E '[d]bus-daemon|[d]bus-broker|[b]usd' \
    || echo "No D-Bus daemon process is visible in this PID namespace."

section "Base bus round trip: org.freedesktop.DBus.ListNames"
if command -v dbus-send >/dev/null 2>&1; then
    run timeout "$TIMEOUT_SECONDS" dbus-send --session \
        --dest=org.freedesktop.DBus \
        --type=method_call --print-reply \
        /org/freedesktop/DBus org.freedesktop.DBus.ListNames
else
    echo "SKIP: dbus-send is unavailable."
fi

section "Portal ownership: org.freedesktop.portal.Desktop"
if command -v dbus-send >/dev/null 2>&1; then
    run timeout "$TIMEOUT_SECONDS" dbus-send --session \
        --dest=org.freedesktop.DBus \
        --type=method_call --print-reply \
        /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
        string:org.freedesktop.portal.Desktop
else
    echo "SKIP: dbus-send is unavailable."
fi

section "Portal OpenURI introspection"
if command -v gdbus >/dev/null 2>&1; then
    run timeout "$TIMEOUT_SECONDS" gdbus introspect --session \
        --dest org.freedesktop.portal.Desktop \
        --object-path /org/freedesktop/portal/desktop
else
    echo "SKIP: gdbus is unavailable."
fi

section "Result"
echo "Interpretation:"
echo "- ListNames must succeed before portal or URL-opening failures are meaningful."
echo "- NameHasOwner=false means the base bus works but no portal is running."
echo "- A timeout or closed connection during ListNames means the bus itself is unhealthy."
