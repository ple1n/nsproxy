# Route-map examples

These files are standalone `RoutePrefs` inputs containing `default_route` and
`route_map`, using concrete `RoutingKey` to `RoutingResovled` pairs. Their
domains are lowercase fully qualified names with trailing dots. They target
HTTPS port 443 and use the proxy ID from
the existing local route configuration; replace that ID if the destination
profile does not have the same proxy.

```sh
sp route routing_examples/dnf.json --apply-to <PROFILE>
sp route routing_examples/huggingface.json --apply-to <PROFILE>
```

Use `--replace` to clear the profile's current route map before applying an
example.
