# Adaptive mode

I'm introducing a new mode of TUN routing. 

This mode does not have any anonymity or identity segregation.

This mode is ideally suited for cases like package managers, which do not need extra anonymity. Example, you spin up an overlay container named `mixed`, do `sp enter mixed fish -u 0`, and do `dnf upgrade`.

When we are informed of a domain/IP through DNS or TUN, we assess whether the host is reachable directly, or by proxy.

`sp serve` keeps process-wide internal routing preferences for hosts it has encountered.

For each SOCKS5 destination (`WireAddress`, including its port), direct and each individual proxy route have separate performance statistics. Domain targets are case-folded and have a trailing dot removed before keying. TCP attempts record connect latency and success/failure. TCP and UDP relay rates are kept separately. The TCP relay records successful forwarded-write events; UDP records successfully forwarded datagrams. Both directions use 100 ms buckets over a five-second rolling window, with at least one second and three events required to qualify a sample. Qualified samples update serve-side route statistics while traffic is active and again on TCP completion. Connection lifetime and idle time before the first or after the last data event are not used as the throughput denominator. Qualified samples feed duration-weighted exponential averages with a 30-second half-life; stale estimates become unknown. UDP send-side observations indicate successful handoff to the local tunnel adapter, not confirmed remote receipt. These are observed relay goodput rates, not maximum route capacity or proof that the route caused a low rate. Estimates are process-local, are not persisted, and are available in the Traffic tab with latest sample evidence on hover.

The Traffic panel also supports a host-wide direct/proxy override. The selected route is applied and persisted by `sp serve`; it covers all ports and both TCP and UDP for that host. The per-host route action is separate from adaptive route selection.

The adaptive mode first tries direct for 10 seconds, then starts a proxied attempt without immediately cancelling the direct attempt. If both routes succeed, compare latency and throughput; prefer proxy when direct download throughput is below 1,000,000 bytes/s. `allow_replay` in HotConfig controls whether the original request may be replayed; it defaults to `true` in adaptive mode.

Adaptive route selection, concurrent fallback, and `allow_replay` are not implemented yet. Per-target/per-route performance statistics are collected separately from TCP streams and UDP datagrams.

