

# systemd-resolved

sysetemd has a DNS unix socket at `/run/systemd/resolve/io.systemd.Resolve`

## for overlay mode 

- `resolv.conf` alone isnt enough. `/etc/nsswitch.conf` takes precedence. 
- therefore bind mount overlay nsswitch.conf
- minimal nsswitch.conf to use only explicit DNS resolver:
  ```
  hosts: files dns
  ```
- then set `/etc/resolv.conf`:
  ```
  nameserver 100.68.0.2
  ```
- this prevents `libnss_resolve.so` from being loaded; glibc uses `libnss_dns.so` which does UDP to the configured nameserver only

## for pivot mode

- IPC isolation is irrelevant
- the socket can be hidden from the sandbox via pivot_root (new root without `/run/systemd/resolve/`)
