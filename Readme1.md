# NSProxy

Kernel-namespaces-based alternative to proxychains.

> Part of Accessible OPSEC series (if there even is).

## quick start

```sh
# download or compile
sudo ./nsproxy install -s
# geph is a well known tool with good opsec
# this command sets up a namespace and enters it giving you a shell
sproxy geph
# now open another terminal
sproxy librewolf # lauches librewolf with a prompt for choosing a profile
# you can use different profiles for different namespaces
sproxy fractal  # lauches `fractal` by directing running the command ie not using flatpak
# fractal is a matrix client written in Rust
```

apart from biased shortcuts, the standard commands are....

here is the case where you connect to a proxy from another computer in a local network

```sh
# get the binary to the device you want to proxy by whatever way, like kde-connect
kdeconnect-cli --share ./target/debug/nsproxy -d _a82d921a_aaa3_495f_978e_433a17395f3e_
# now run this one liner to install it to /usr/bin/ of course this doesnt work with nixos
sudo ./nsproxy install -s
# must use sproxy (which has SUID flag set) to initialize userns
sproxy userns
# subsequent operations do not need the SUID binary
# make the container
nsproxy socks --proxy socks5://192.167.1.2:9909
# you may also not use userns, which has better compatibility especially for system softwares, such as distribution's package managers
sproxy socks --proxy socks5://192.167.1.2:9909 --root
# this affects system wide DNS configuration temporarily though
```

and it enters a shell which is proxied as instructed.

for **flatpak** apps you can always run "flatpak run com.someapp" inside a shell like above. at least by the time I'm writing this, flatpak does not run the app through another process outside the namespace.....

## more

It's recommended to use the veth + tun2proxy method.

```bash
./nsproxy install -s # installs nsproxy and sproxy to your /usr/local (requires root) and makes sproxy suid
# it assumes sproxy is in the same directory as its nsproxy binary
# even though sproxy is SUID, it still runs SUDO to check your permission
sproxy new --mount --veth --tun2proxy ./test_proxy.json # gives you a shell inside a proxied container
# later you may
sproxy node 1 run # enter that container from another shell
```

![](./pic.png)

## Rationale

- Firefox and its derivatives, leak traffic even with SOCKS5 proxy configured
    - Most browsers, Firefox, Floorp (false advertised malware), and even Librewolf, caused my firewall to pop up when I opened it.
        - which by my OPSEC standard is unacceptable.
- Proxychains may silently fail and leak traffic (but it's a great tool if you put it in a netns which nullfies the downsides)
    - because it avoids the roundtrip of TUN and make the app connect to SOCKS5 endpoint directly
- Nsproxy creates containers which better suits the OPSEC use case than [sing-box](https://github.com/SagerNet/sing-box)
- [Tun2socks](https://github.com/xjasonlyu/tun2socks) does not have virtual DNS
- VPNs (in the sense the binaries VPN vendors distribute) do not care about the OPSEC usecase.
- Portmaster does not handle the use case this tool is concerning.
    - I find it dishonest because its per-app-vpn feature only works with *their* VPNs
- Opensnitch does not have the `redirect/restrict programs to certain net interfaces, addresses (of socks5)` feature.
- Easider debugging of the network due to netns seperating traffic. You have create one netns for each process you want to debug.

## The usecase

- You use non-conventional protocols. You need userspace TUNs.
- You want to have some apps proxied, and others not.
- You have a diverse need for proxied routing, and you don't want to read a ton of docs.
- You don't want to mess with other parts of your system.
- You want to proxy Flatpak apps.

Examples

- Librewolf/Firefox/MullvadBrowser with multiple profiles, one per container.
- Monerod
- Zcash
- Vscode

## We've got you covered

Root or not

- `sproxy` requires root but less trouble
    - connects the container to your root/initial netns through veth (max performance)
    - `sproxy` is just a wrapper that starts `nsproxy`.
- `nsproxy userns`
    - initialises a user ns. This is a one-time operation, it just mounts them
    - It's possible to not mount the NS and have a long-running process, but it's not implemented
- `nsproxy socks2tun --new-userns`
    - requires no root, throughout the whole process.

The proxy

- The current recommended usage is `sproxy veth -t <config>`
    - Provides a TUN for non-socks5-capable programs
    - Provides a veth to your root net ns to access your proxies
- If your proxy client is opensourced, it can be made to accept a socket from nsproxy
    - Nsproxy will create a container and you can access the proxy through a SOCKS5 endpoint in the container.
- If your proxy is opensourced and has custom TUN logic, it can be made to accepet the TUN file descriptor from nsproxy
- If your proxy can not be modified, you can use the `socks2tun` subcommand to connect to its SOCKS5 endpoint.

The app

- If your app doesn't work with SOCKS5
    - If your app works with LD_PRELOAD, you don't need a TUN.
        - You may use proxychains inside an Nsproxy container
        - Nsproxy creates a SOCKS5 endpoint in the container that is passed to the proxy
    - Nsproxy may create a TUN and pass it to the proxy
    - Nsproxy may create a TUN and route it to the proxy's SOCKS5 endpoint
- If your app works with SOCKS5
    - You just connect to the SOCKS5 endpoint in the container
    - You can use the `veth` method

## Fix flatpak networking, sideways.

You can run `nsproxy watch ./test_proxy.json` to automatically proxy flatpak apps.

Currently it's not recommended (bad for anonymity) to have multiple instances of an app because the data could not be segregated, see [the issue](https://github.com/flatpak/flatpak/issues/1170).

## Development

- Netlink manipulation (including Netfilter) libraries in Rust
- Tun2socks implementation with [ipstack](https://github.com/narrowlink/ipstack)
    - Virtual DNS included
    - The original branch used [tun2proxy](https://github.com/blechschmidt/tun2proxy) but the `smoltcp` it uses has bugs which makes it unusable.
- Rangemap based IP allocation (or suitable object) library
- Forked PidFd with `impl AsFd for PidFd`
- Mounting network namespaces, preparing them for use, everything, in Rust.

## Why doesn't my IPV6 work ?

I've been using nsproxy with Geph. For some reason I had to use IPV6, which didn't work in nsproxy. I found out an ipv6 address of `exmaple.com` and put it in the browser, which surprisingly loaded.

The source code of geph shows it doesn't support ipv6. After some wireshark-ing, apparently the browser (librewolf) treated the ipv6 address as a domain, passed it to geph's socks server.

Librewolf is not complying with socks5 protocol, and concidentally sidestepped the code in Geph that throws errors upon ipv6.

After more debugging, it turned out the traffic was sent directly without proxying, because the addr was being labelled as a domain by librewolf, and then catogorized as "should not proxied" by geph.

If I were to keep anonymity, that would be a total disaster.
