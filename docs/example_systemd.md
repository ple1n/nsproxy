
Nsproxy can handle systemd services

Example config that works 

```ini
[Unit]
Description=Nix Daemon
Documentation=man:nix-daemon https://nixos.org/manual
RequiresMountsFor=/nix/store
RequiresMountsFor=/nix/var
RequiresMountsFor=/nix/var/nix/db
ConditionPathIsReadWrite=/nix/var/nix/daemon-socket

[Service]
ExecStart=sp enter basic /usr/bin/nix-daemon -- --daemon
KillMode=process
LimitNOFILE=1048576
TasksMax=1048576
Delegate=

[Install]
WantedBy=multi-user.target
```

where `basic` is an overlay net-proxied container which introduces minimal breakage. 

I configured the network to proxy all traffic but a few selected hosts, to speed it up.