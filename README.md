# nsproxy v3

It is 

1. a compatbility layer from sockets to SOCKS
2. replacement for `sudo` when you work with network namespaces heavily
3. a handy tool to isolate traffic of select processes, where you can launch Wireshark inside to inspect the containerized traffic. 
4. a containerization-capable daemon for self-hosted web stacks, where you get virtual local domains assigned with zero setup
5. an extra layer to harden each Librewolf profile with privileged namespaces

- Maximal compatiblity. Run system package managers, obscure softwares, arbitrary AppImages, proxied.
- Minimal trust. Softwares are no longer entrusted to use proxies and DNS properly. Nor should you assume it.
- High concurrency. Async TCP stack written in Rust, native, although the need for a 'compatibility layer' suggests there is something wrong already. 
- Maximal portability, minimal dependencies. Run nsproxy without desktop environment and chroot to rescue your system. 
- Non-sandbox. Not intended to be a sandbox. Ask flatpak to incorporate features in this project, if you want. 
- Not a new docker. This is a handy tool that follows the user loyally. 

## Minimal configuration state

No `/etc/`, `/usr/`, `$xdg`, and such hierarchy of fallbacks that serve no purpose but confusion. 

Nsproxy only takes command line arguments, one hot-reloaded config file, reads procfs and communicates with kernel through netlink.

## Virtual DNS and files served through a TUN 

See `./nsproxy.json` which is similar to the configuration I use. The feature is particularly handy in cases of self-hosting.

```fish
sproxy enter
sudo setcap CAP_NET_BIND_SERVICE=+ep (which node)
npx vite preview --port 80
```

I run Cinny in an nsproxy container and direct virtual DNS to resolve multiple hosts to localhost, which enables me to use multiple accounts on Cinny.

Nsproxy can also serve static files directly through the TUN device.

## dev

Stop making modules private. Dependencies Shall hide nothing from me. 80% of forks in this project are due to some items being private.

Encapsulation is a failure, a failed feature coming from OOP.
