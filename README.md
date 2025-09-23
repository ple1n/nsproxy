# nsproxy v3

a compatbility layer from sockets to SOCKS

- Maximal compatiblity. Run system package managers, obscure softwares, arbitrary AppImages, proxied.
- Minimal trust. Softwares are no longer entrusted to use proxies and DNS properly. Nor should you assume it.
- High concurrency. Async TCP stack written in Rust, native, although the need for a 'compatibility layer' suggests there is something wrong already. 
- Maximal portability, minimal dependencies. Run nsproxy without desktop environment and chroot to rescue your system. 
- Non-sandbox. Not intended to be a sandbox. Ask flatpak to incorporate features in this project, if you want. 
- Not a new docker. This is a handy tool that follows the user loyally. 