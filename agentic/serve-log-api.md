# Inspect app network activity with `sp`

Use this as an operator agent investigating an app in an `sp` profile. These endpoints expose `sp serve` runtime/proxy history, not arbitrary application stdout or stderr.

## Reach the API

The HTTP API listens on port `17890` inside the profile network namespace. From a shell in that namespace, use `http://127.0.0.1:17890`; from elsewhere, use an address that can reach the profile network. The listener has no authentication, so do not expose it to untrusted networks.

The React console is embedded when `crates/diag/web/dist/index.html` exists and the build has not opted out with `--no-web`. `./build-ui.sh` includes it by default; `./build-ui.sh --no-web` omits the React files and serves a small enablement page at `/`. The JSON and event-stream API endpoints remain available either way. `deploy.sh` forwards build arguments to `build-ui.sh`.

## Investigate connections

- For structured TCP/UDP activity, query `GET /v1/connections?age_seconds=<window>[&ip=<address>]`. It includes active and recently finished flows, endpoints, timestamps, and recorded events. `age_seconds` defaults to 60.
- To ask nsproxy's live routing policy without sending traffic, query `GET /v1/route?dst=<IP>&src=<IP>&port=<PORT>&protocol=tcp|udp`. All four parameters are required because policy can depend on source address, transport protocol, and destination port. The response contains the input context and the router's resolved `Direct`, `NATByTUN`, `ProxyResovled`, or `Drop` decision. This is not a kernel FIB lookup; virtual-IP destinations are checked against the running Virtual DNS mapping.
- To check what a virtual IP mapped to at a time, query `GET /v1/virtual-ips/<ip>?at_us=<timestamp>`.
- For surrounding runtime logs, query `GET /v1/logs?from_us=<start>&to_us=<end>[&limit=<count>&offset=<count>]`. Times are inclusive Unix-epoch microseconds. Start with a narrow window and locally inspect `target`, `message`, and `fields` for DNS, routing, connection, timeout, and IP details; the endpoint does not filter log text.

From the host, query the last five minutes like this (replace the profile name):

```sh
PROFILE=my-app
to_us=$(date +%s%6N)
from_us=$((to_us - 300000000))
sp enter "$PROFILE" -- curl --get http://127.0.0.1:17890/v1/logs \
  --data-urlencode "from_us=$from_us" \
  --data-urlencode "to_us=$to_us" \
  --data-urlencode "limit=1000"
```

Use `limit` up to 5000 and increase `offset` to page through results.

`/v1/history` reports the oldest retained log timestamp. `400` means invalid query parameters; `410` means the requested in-memory history is unavailable or evicted. These endpoints do not read persisted files.
