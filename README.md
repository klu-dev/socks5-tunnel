# socks5-tunnel

[*tokio2-socks5*](https://github.com/klu-dev/tokio2-socks5) is socks5 proxy which do not have authentication. Socks5 protocol supports username/password authentication. But most applications such Chrome, do not support socks5 authentication and consider it is not safe. There is a scenario that users want to have a private socks5 proxy and do not want unauthenticated users to use this proxy. *socks5-tunnel* aims to address this scenario.

## Usage

1. First, need to install [`rust`](https://www.rust-lang.org/), then build the program in project directory

```
$ cargo build
```

The binary `socks5-tunnel` for Linux or `sokcs5-tunnel.exe` for Windows are in `socks5-tunnel\target\debug`.

2. Generate two pair secret keys. 

```
D:\code\socks5-tunnel\target\debug>.\socks5-tunnel.exe -g
Private key:
f8084cd3d6c9fc713cb2bb645dbdd065c7c639d67b296ee73335b06fae26c642
Public key:
4d67400cfb0d88d60383dc1a06bf3db241d0b292d344c808d142f30bed530569

D:\code\socks5-tunnel\target\debug>.\socks5-tunnel.exe -g
Private key:
a80cd6eeda9e11907a17c40e05ee5f7f31924824ae25a344b9ff2796918f2258
Public key:
4ab933848af90179f344cc3f955c12d82cf7eec1c1558566b731252719c92525
```

**Note: You must generate the secret keys yourself. Do not use the keys here. Do not leak your secret keys**

3. Copy program to server machine and run it in server mode:

```
D:\code\socks5-tunnel\target\debug>.\socks5-tunnel.exe -m Server -l 0.0.0.0:1080 -k f8084cd3d6c9fc713cb2bb645dbdd065c7c639d67b296ee73335b06fae26c642 -b 4ab933848af90179f344cc3f955c12d82cf7eec1c1558566b731252719c92525
Work in server mode...
Listening on: /ip4/127.0.0.1/tcp/1080
```

4. Copy program to client machine and run it in client mode. Assuming your server machine IP is 192.168.1.2

```
D:\code\socks5-tunnel\target\debug>.\socks5-tunnel.exe -m client -l 127.0.0.1:1080 -p 192.168.1.2:1080 -k a80cd6eeda9e11907a17c40e05ee5f7f31924824ae25a344b9ff2796918f2258 -b 4d67400cfb0d88d60383dc1a06bf3db241d0b292d344c808d142f30bed530569
Work in client mode...
Listening on: /ip4/127.0.0.1/tcp/1080
```

5. Set chrome proxy.

One method for Chrome using socks5 proxy, start the chrome program with parameter:

```
--proxy-server="SOCKS5://127.0.0.1:1080"
```

For example in Windows, run command:

```
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --proxy-server="SOCKS5://127.0.0.1:1080"
```

Another way is duplicating chrome shortcut. Add ` --proxy-server="SOCKS5://127.0.0.1:1080"` in `Target` item of `Shortcut` tab properties.

6. Show log.

Add environment RUST_LOG=info/debug/trace *before* start the program.

Windows cmd:

```
set RUST_LOG=info
```

Linux bash:

```
export RUST_LOG=info
```

## Solution

```
                      ______________________________________________
                      | __________________________________________  |
         tcp          | |           Noise Encrypt Tunnels         | |          tcp
Browser -----> Client Mode Proxy                            Server Mode Proxy ------> Destination Web Site
```

Client proxy run in machine which Browser runs, accept connection and create Noise encrypt connection to server proxy.  It transfer data from Browser to Server proxy transparently. Server proxy run in machine which can access destination web sites. Server proxy implement socks5 protocol and create connection to destination web sites. Data flows between Browser, Client proxy, Server proxy and Destination web sites.

Very connection from Browser will create a Noise encrypt connection between client proxy and server proxy to deliver data from browser to destination web site. An alternative use multiplexer between client proxy and server proxy on one connection to decrease the number of connections. One multiplexer is [*Yamux*](https://github.com/hashicorp/yamux/blob/master/spec.md). The problem is [*Yamux*](https://github.com/hashicorp/yamux/blob/master/spec.md) has no priority management. Different stream has the same priority. In extreme cases, one stream may occupy the whole traffic and causes other streams starvation. But in some scenario such as connection number limitations case, multiplexer is useful.

## Secure Analysis

Noise encrypt tunnel uses Noise [KK](https://noiseexplorer.com/patterns/KK/) mode. It use fixed key pair as authentication function. Assuming client proxy and server proxy obtain peer public key, which can be generated through command `.\socks5-tunnel.exe -g`, in advance through other ways. Attackers need to know server public key and client private key, otherwise they can not connect to server.

Compared with https proxy, the noise protocol is more simple without CA and has been used by [*WireGuard*](https://www.wireguard.com/)

## Future work

* Support multiplexer for noise tunnel

* Add *Relay* mode to relay data from start proxy to server proxy

## How is this module organized?

    crypto                                    # porting from [libra](https://github.com/libra/libra) to provide API for secret key   operations
    crypto-derive                             # porting from [libra](https://github.com/libra/libra) to provide macros used by crypto library
    memsocket                                 # porting from [libra](https://github.com/libra/libra) to simulate transport  in memory used for tests
    src
    ├── noise                                 # porting from [libra](https://github.com/libra/libra) to implement noise futures and transport
    ├── transport                             # porting from [libra](https://github.com/libra/libra) to abstract general protocol concept
    ├── build_transport                       # Upgrade tcp transport to noise transport
    ├── command                               # Parse command arguments
    ├── end_node                              # server mode proxy
    ├── Server                                # sransport listening stream accept
    ├── start_node                            # client mode proxy

# License

This project is licensed as [Apache 2.0](https://github.com/libra/libra/blob/master/LICENSE).

