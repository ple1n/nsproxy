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

## Setup

The recommended setup is to have both `nsproxy` and `sproxy` available. 

```bash
./nsproxy -s
```

`sproxy` the wrapper is nessitated because in some cases the environment `sudo` creates breaks the apps, such as AppImages.

Let's start from the simplest use case

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

## To check the state of namespaces

`nsproxy info` should print a summary of all living nodes. 

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

## Why even bother

- Proxychains uses LD_PRELOAD, which in some cases fails to capture the traffic.
- Uncontainerized usage of socks5, such as having a browser that connects to `localhost:a_certain_socks5_port` gives the browser too much privilege, which results in risk. 

The WebRTC leak is a notorious case that got some political dissents arrested, because WebRTC somehow didn't go through the Firefox socsk5 proxy as configured. 

Secondly, based on my past usage, it's really hard to configure everything right, when it has a dozen of fields about proxy littered everywhere. I sometimes ended up having Firefox leak DNS requests, unproxied. 

- Why not just use Docker?

A: I already wrote this and it's based on the same primitives Docker uses. 

