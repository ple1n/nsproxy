#!/usr/bin/env bash
# test_dbus_open.sh — Test D-Bus URL opening (xdg-open via session bus)
#
# This tests the most important D-Bus feature: opening a URL via the portal
# (org.freedesktop.portal.OpenURI) or xdg-open, which uses the session bus.
#
# Usage:
#   ./devscripts/test_dbus_open.sh [profile] [url]
#
#   profile   nsp3 profile to enter (default: "test" or $NSP_PROFILE)
#   url       URL to open (default: https://example.com)
#
# The script can be run both OUTSIDE the container (to verify dbus is reachable)
# and INSIDE the container (via `sp enter <profile>` or `sp sandbox <profile>`).

set -euo pipefail

PROFILE="${1:-${NSP_PROFILE:-}}"
URL="${2:-https://example.com}"

echo "=== D-Bus URL open test ==="
echo "URL: $URL"
echo ""

# --- 1. Show DBUS_SESSION_BUS_ADDRESS ---
echo "--- DBUS_SESSION_BUS_ADDRESS ---"
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    echo "  NOT SET — D-Bus session bus address is missing"
    echo "  (If running inside a container with 'block' mode, this is expected)"
    echo "  (If testing 'pass' or 'proxy' mode, this is a problem)"
    DBUS_PRESENT=0
else
    echo "  $DBUS_SESSION_BUS_ADDRESS"
    DBUS_PRESENT=1
fi
echo ""

# --- 2. Check dbus-daemon / bus socket reachability ---
echo "--- Socket reachability ---"
if [ "$DBUS_PRESENT" -eq 1 ]; then
    # Extract socket path from address like unix:path=/run/user/1000/bus or unix:abstract=...
    SOCK_PATH=""
    if [[ "$DBUS_SESSION_BUS_ADDRESS" == unix:path=* ]]; then
        SOCK_PATH="${DBUS_SESSION_BUS_ADDRESS#unix:path=}"
        # strip trailing ,... if any
        SOCK_PATH="${SOCK_PATH%%,*}"
    fi
    if [ -n "$SOCK_PATH" ]; then
        if [ -S "$SOCK_PATH" ]; then
            echo "  Socket exists: $SOCK_PATH"
        else
            echo "  Socket MISSING: $SOCK_PATH"
        fi
    else
        echo "  (abstract socket or non-path address — cannot check directly)"
    fi
else
    echo "  Skipped (no address)"
fi
echo ""

# --- 3. dbus-send ping to org.freedesktop.DBus ---
echo "--- dbus-send: ping org.freedesktop.DBus ---"
if command -v dbus-send >/dev/null 2>&1 && [ "$DBUS_PRESENT" -eq 1 ]; then
    if dbus-send --session --dest=org.freedesktop.DBus \
        --type=method_call --print-reply \
        /org/freedesktop/DBus \
        org.freedesktop.DBus.Peer.Ping 2>&1; then
        echo "  PASS"
    else
        echo "  FAIL"
    fi
else
    echo "  Skipped (dbus-send not found or no session bus)"
fi
echo ""

# --- 4. Check org.freedesktop.portal.OpenURI ---
echo "--- portal: org.freedesktop.portal.OpenURI introspect ---"
if command -v dbus-send >/dev/null 2>&1 && [ "$DBUS_PRESENT" -eq 1 ]; then
    if dbus-send --session --dest=org.freedesktop.portal.Desktop \
        --type=method_call --print-reply \
        /org/freedesktop/portal/desktop \
        org.freedesktop.DBus.Introspectable.Introspect 2>&1 | grep -q OpenURI; then
        echo "  PASS — OpenURI interface found"
    else
        echo "  FAIL or NOT AVAILABLE — portal may not be running"
    fi
else
    echo "  Skipped"
fi
echo ""

# --- 5. xdg-open (dry run via busctl / gdbus if available) ---
echo "--- gdbus: call OpenURI (dry run with empty parent handle) ---"
if command -v gdbus >/dev/null 2>&1 && [ "$DBUS_PRESENT" -eq 1 ]; then
    echo "  Calling org.freedesktop.portal.OpenURI.OpenURI with URL: $URL"
    if gdbus call \
        --session \
        --dest org.freedesktop.portal.Desktop \
        --object-path /org/freedesktop/portal/desktop \
        --method org.freedesktop.portal.OpenURI.OpenURI \
        "" "$URL" "{}" 2>&1; then
        echo "  PASS — portal accepted the call"
    else
        echo "  FAIL — portal rejected or not present"
        echo "  (may still work if xdg-open falls back to other methods)"
    fi
else
    echo "  Skipped (gdbus not found or no session bus)"
fi
echo ""

# --- 6. xdg-open fallback ---
echo "--- xdg-open fallback test ---"
if command -v xdg-open >/dev/null 2>&1; then
    echo "  xdg-open is available"
    echo "  To actually open the URL run: xdg-open '$URL'"
    echo "  (not run automatically to avoid opening browsers in test mode)"
else
    echo "  xdg-open not found"
fi
echo ""

echo "=== Summary ==="
if [ "$DBUS_PRESENT" -eq 1 ]; then
    echo "Session bus is SET. Run inside the target container to test proxy/pass mode."
else
    echo "Session bus NOT set. Expected in 'block' mode or outside a container."
    echo "To test proxy mode: sp enter <profile>  (with dbus=proxy in TemplateConfig)"
    echo "To test pass mode:  sp enter <profile>  (with dbus=pass in TemplateConfig)"
fi

if [ -n "$PROFILE" ]; then
    echo ""
    echo "To run inside profile '$PROFILE':"
    echo "  sp enter $PROFILE -- bash devscripts/test_dbus_open.sh '' '$URL'"
fi
