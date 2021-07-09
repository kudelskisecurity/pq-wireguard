# PQ-WireGuard

In this branch, we integrate our [tweaked implementation of the crystals post-quantum algorithms](https://github.com/kudelskisecurity/crystals-go/tree/tweakedKyber) in the [Go implementation of Wireguard](https://github.com/WireGuard/wireguard-go) following the [Fujioka contruction](https://link.springer.com/chapter/10.1007/978-3-642-30057-8_28).
Please refer to [our blog-post](https://wordpress.com/post/research.kudelskisecurity.com/15437) for more information.

## WIP

We are currently working on overriding the [`wg(8)` commands](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to allow the users to input Kyber keys.
For now, the key pair and the peers' key must be given within a configuration file when starting the interface, using the `-c` or `--config_file` flag followed by the .conf file. We included examples of such file (see [peer0.conf](https://github.com/kudelskisecurity/pq-wireguard/blob/tweakedKyber/peer0.conf)) to showcase the accepted format and required fields.

## Building

This requires an installation of [go](https://golang.org) ≥ 1.13.

```
$ git clone https://github.com/kudelskisecurity/pq-wireguard
$ cd pq-wireguard
$ go build
```

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ ./wireguard -c peerX.conf wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ ./wireguard -f -c peerX.conf wg0
```

When an interface is running, you may use the usual `ip(8)` and `ifconfig(8)` commands `ip addr add X.X.X.X/X dev wg0` and `ip link set wg0 up`.
See the original wireguard-go [README](https://git.zx2c4.com/wireguard-go/REAMDE.md) for more details

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Generating the .conf file

The public and private keys can be generated and printed using the `--keygen` flag.
```
$ ./wireguard --keygen
```

The IP address to use as endpoint can be extracted using the `ip addr` command.
The port to be used can be randomly assigned among the free ports.
The protocol version is set to 1, the booleans `replace_allowed_ips` and `replace_peers` are set to true.

## Demo

You can watch below the video of two peers being configured side-by-side.

https://drive.google.com/file/d/1kjXPb9SclK9umB4hkgHnJSDSagKoxhQX/view?usp=sharing

## License

    Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
