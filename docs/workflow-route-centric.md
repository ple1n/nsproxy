# Route preferences

`RoutePrefs` is the transferable routing subset of `HotConfig`. It contains the
same two fields:

- `default_route`: the profile-wide fallback policy (`HotRoute`).
- `route_map`: a map from `RoutingKey` to a concrete `RoutingResovled`.

Route preference files are deserialized as `RoutePrefs`, not as complete
`HotConfig` documents. They contain neither symbolic route names nor unrelated
profile settings.

```json
{
  "default_route": "NoProxy",
  "route_map": [
    [
      { "Host": ["huggingface.co.", 443] },
      {
        "ProxyResovled": {
          "target": { "DomainAddress": ["huggingface.co.", 443] },
          "id": "..."
        }
      }
    ]
  ]
}
```

Host keys and domain targets are canonical lowercase fully qualified names
with a trailing dot. Deserialization normalizes every domain in both fields;
if normalization makes two keys collide, the document is rejected. Incoming
host lookup keys use the same normalization.

`sp route <FILE> --apply-to <PROFILE>` updates `default_route` and merges
`route_map` entries by key. `--replace` replaces the complete route map. The
default route from the file is applied in either mode. `sp route export`
captures both fields, and `--make-container` writes them before starting the
new profile and its serve process.

Route-map lookup checks a hostname or destination IP, preferring the exact
port before the any-port entry. A miss falls back to `default_route`. IP keys
must identify final destinations, never virtual ingress addresses.

Example command to adaptively proxy `dnf`

```
sp route ~/nsp3/routing_examples/dnf.json --make-container dnf fish
```