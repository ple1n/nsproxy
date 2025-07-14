# nsproxy

ie. Kernel-Network-Namespace-Proxy

Available commands 

```bash 
$ nsproxy 
    # the CLI binary for all operations
$ sproxy 
    # an SUID wrapper that simply calls nsproxy
```

The networking here is mostly targeted at censorship-ridden users, such as in China, Russia, Iran. Hence it mainly uses userspace networking, rather than *wireguard* and such commonly used tooling. 

## Security model

This tool provides defense against accidental leaks of IP, through TCP, UDP or DNS, which is common for softwares not designed with net-proxying in mind.

__*Not designed to contain malwares*__. Further, for convenience, the tool allows entering net-ns without _sudo_ through the SUID binary. (This saves my time immensely)

## Setup

The recommended setup is to have both `nsproxy` and `sproxy` available. 

```bash
./nsproxy install -s [--dstdir DSTDIR] 
```

`sproxy` the wrapper is nessitated because in some cases the environment `sudo` creates breaks the apps, such as AppImages

> the initial use case that prompted me to make this tool is that Zcash desktop client didn't work with proxychains, and it was shipped in AppImage. Manually scripting with netns based off stackoverflow didn't work either due to SUDO perm issues.

Let's start from the simplest use case

In most cases you just need a separate network namespace with a pair of veths. You can use the proxy through the veth as usual, provided that you listen the proxy on the veth.

```sh
sproxy new --veth
# have your proxy listen on the other end of veth
```

This is also more performant unlike the TUN-method which needs a roundtrip to userspace and a lot of copying... unless you have apps that are not compatible with SOCKS5. At that moment anything works is a life saver.......

> Direct use of socks5/http proxy is always more efficient, because otherwise this tool is used as a compatibility layer that translates Unix sockets with TUN to the proxy protocol, which involves several times of memory copying and costs of synchronization and syscalls.

## To use it with Tor 

```json
{
  "proxy": {
    "proxy_type": "Socks5",
    "addr": "127.0.0.1:9150",
    "credentials": null
  },
  "ipv6_enabled": true,
  "dns": "Handled",
  "dns_addr": "127.0.0.1",
  "bypass": [],
  "state": "/tmp/tun2dns_torb"
}
```

This is the configuration [file](./tor_browser.json) for Tor as a proxy.

Run 

```bash
sproxy new -t ./tor_browser.json
```

Nsproxy then creates a node, which represents a network namespace.

Notice in default mode it intensively utilizes *systemd* to manage the daemons.

After extensive logging it drops you to a shell (or starts the program you specified)

You can check the state of that network namespace, netns. 

```
➜  nsproxy git:(tun2socks5) ✗ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host proto kernel_lo 
       valid_lft forever preferred_lft forever
2: tunp: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 9000 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 100.64.0.2/16 brd 100.64.255.255 scope global tunp
       valid_lft forever preferred_lft forever
    inet6 fe80::dcf2:7e62:6f4c:cd01/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever

```

You can start any process in this shell, and the networking is completely isolated from the host network stack.

Option `-m` mounts the namespace to a file. Otherwise the namespace gets garbage-collected once all the processes inside die. 

In any case, namespaces are cleared every reboot. 

## Now I want to proxy with something other than Tor?

Command `nsproxy gen --proxy socks5://someip -o output.json` should generate a config file, to serve as your starting point.

```
./target/debug/nsproxy gen --help
Generate typical config for Tun2proxy

Usage: nsproxy gen [OPTIONS] --proxy <URL> [STATE]

Arguments:
  [STATE]
          

Options:
  -p, --proxy <URL>
          Proxy URL in the form proto://[username[:password]@]host:port

  -o, --output <OUTPUT>
```

## Troubleshooting

One common problem is about DNS 

Try 

 - `dig yourdomain.com @some-dns-ip-of-your-choice`
 - `cat /etc/resolv.conf`

Usually there is some problem with `/etc/resolv.conf`

Nsproxy comes with a simple fix for that 

```
➜  nsproxy git:(tun2socks5) ✗ nsproxy set-dns --help
Override DNS configuration for the mount namespace you are in. It performs a bind mount

Usage: nsproxy set-dns
```

You have to enter the namespace, and do the command in the said shell.

NSProxy must be installed to paths that SELinux allows; otherwise you get 203/Exec systemd error, if you choose to use systemd.

## Handle system requests on opening links

Many apps open links through `xdg-open` or the APIs thereof, or the like.

If you have multiple instances of a browser in different net-ns, it's uncertain which browser will be used.

For `xdg-open`, you can patch the `.desktop` file it uses, which is configured by `xdg-settings`.

Example command line, `nsproxy enter 0 librewolf -- -p base_p`, which is

```ini
[Desktop Entry]
Type=Application
Name=LibreWolf
GenericName=Web Browser
StartupNotify=true
Terminal=false
MimeType=application/json;application/pdf;application/rdf+xml;application/rss+xml;application/xhtml+xml;application/xhtml_xml;application/xml;image/gif;image/jpeg;image/png;image/webp;text/html;text/xml;x-scheme-handler/http;x-scheme-handler/https;
Comment=Browse the World Wide Web
Categories=Network;WebBrowser;Security;
StartupWMClass=librewolf-default
Exec=/usr/local/bin/sproxy enter 0 /usr/share/librewolf/librewolf -- -p base_p %u
Icon=librewolf

Actions=new-window;new-private-window;safe-mode;preferences;

[Desktop Action new-window]
Name=New Window
Exec=/usr/local/bin/sproxy enter 0 /usr/share/librewolf/librewolf -- -p base_p %u
[Desktop Action new-private-window]
Name=New Private Window
Exec=/usr/local/bin/sproxy enter 0 /usr/share/librewolf/librewolf -- -p base_p --private-window %u
[Desktop Action safe-mode]
Name=Start in Safe Mode
Exec=/usr/local/bin/sproxy enter 0 /usr/share/librewolf/librewolf -- -p base_p --safe-mode
[Desktop Action preferences]
Name=Show Preferences
Exec=/usr/local/bin/sproxy enter 0 /usr/share/librewolf/librewolf -- -p base_p --preferences

```

Replace `base_p` with your browser profile name.

With this setup, either the librewolf opens a new instance in the designated net-ns, or it opens a new tab in the existing instance.

1. If you set it to `/usr/local/bin/sproxy enter 0 /usr/share/librewolf/librewolf -- %u -p`, it asks you which profile to use, and _experimentally_ when a running instance of the profile already exists, it opens _a new window_ in the instance, which is in the same netns as the running instance.
2. If you set it to `/usr/local/bin/sproxy enter 0 /usr/share/librewolf/librewolf -- %u -p profile1`. Also, experimentally, it opens a new tab in `profile1` when a running instance exists, and creates a new instance when it doesn't, which is _in_ the netns of `node 0`, as specified.

I say experimentally because I did not check the code of librewolf. Who knows if it does "smart detection" and makes unanticipated decisions for me.

You need to run xdg update after.

```sh
sudo update-desktop-database  /usr/share/applications # or the directory you use
```

## Changes

- V2 fixed *major performance issues* with virtual dns implementation

## To check the state of namespaces

`nsproxy info` should print a summary of all living nodes. 

## Why even bother

- Proxychains uses LD_PRELOAD, which in some cases fails to capture the traffic.
- Uncontainerized usage of socks5, such as having a browser that connects to `localhost:a_certain_socks5_port` gives the browser too much privilege, which results in risk. 

The WebRTC leak is a notorious case that got some political dissents arrested, because WebRTC somehow didn't go through the Firefox socsk5 proxy as configured. 

Secondly, based on my past usage, it's really hard to configure everything right, when it has a dozen of fields about proxy littered everywhere. I sometimes ended up having Firefox leak DNS requests, unproxied. 

- Why not just use Docker?

A: I already wrote this and it's based on the same primitives Docker uses. 

## Dev

a tool is available for ./tun2socks5 testing https://github.com/ple1n/dns_stress_test