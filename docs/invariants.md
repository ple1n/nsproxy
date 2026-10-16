# Invariant oriented coding

- All containers must be reproducible from `HotConfig`, `TemplateConfig`, and other declared, runtime-independent inputs. Fresh creation must produce the same functional container and sane initial defaults; correctness must not depend on hand-editing `rootfs/<profile>`.
- Container initialization that must survive recreation belongs in the profile's persistent config or another declared input. Generated state must be initialized idempotently and must not overwrite existing user state on each start.
- Re-running `sp up` for a live profile must reuse its namespace identities and converge on one live namespace keeper and one active `up` daemon. It may replace the daemon process; idempotence means stable runtime state and no duplicate resources, not necessarily a no-op.
- Re-running `sp sandbox` with unchanged config must not pivot twice or stack duplicate mounts. Mount reconciliation must be based on the desired source/target state, and the reported sandbox status must match the mounts actually present.
- If sandbox configuration changes after initial application, `sp sandbox` must either reconcile the changed mounts/settings or explicitly report that teardown/recreation is required; it must not silently report success while retaining stale configuration.
- Repeated startup/recovery must not leave stale sockets, duplicate D-Bus daemons, bind mounts, or veth pairs. Recoverable stale state should be reconciled; unrecoverable state should fail visibly.
- Container-specific input-method defaults, including Fcitx's configured group/method, must be declared in profile config and seeded into persistent profile state. Runtime status that depends on a focused input context must not be treated as the configured default.
