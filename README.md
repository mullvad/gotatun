# GotaTun

A userspace [WireGuard<sup>®</sup>](https://www.wireguard.com/) implementation, and a fork of [BoringTun](https://github.com/cloudflare/boringtun).

### Building

- Library only: `cargo build --lib --no-default-features --release [--target $(TARGET_TRIPLE)]`
- Executable: `cargo build --bin gotatun --release [--target $(TARGET_TRIPLE)]`

#### Installation

By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin gotatun --path .`.

#### Nix

To build the executable, simply run `nix build .#gotatun`. The final binary will be located in `result/bin/gotatun`.

### Running

As per the specification, to start a tunnel use:

`gotatun [-f/--foreground] INTERFACE-NAME`

The tunnel can then be configured using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8), as a regular WireGuard tunnel, or any other tool.

It is also possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `gotatun`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=gotatun WG_SUDO=1 wg-quick up CONFIGURATION`

### Testing

Testing this project has a few requirements:

- `sudo`: required to create tunnels. When you run `cargo test` you'll be prompted for your password.
- Docker: you can install it [here](https://www.docker.com/get-started). If you are on Ubuntu/Debian you can run `apt-get install docker.io`.

## Supported platforms

Target triple                 |Binary|Library|
------------------------------|:----:|------|
x86_64-unknown-linux-gnu      |  ✓   | ✓    |
aarch64-unknown-linux-gnu     |  ✓   | ✓    |
aarch64-apple-darwin          |  ✓   | ✓    |
x86_64-pc-windows-msvc        |      | ✓    |
x86_64-pc-windows-gnullvm     |      | ✓    |
aarch64-pc-windows-msvc       |      | ✓    |
aarch64-pc-windows-gnullvm    |      | ✓    |
x86_64-linux-android          |      | ✓    |
aarch64-linux-android         |      | ✓    |
aarch64-apple-ios             |      | ✓    |

<sub>Other targets may work, but we only test for these</sub>

#### Linux

`x86-64`, and `aarch64` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`gotatun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi gotatun`. sudo is not needed.

#### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

---

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall be licensed as above, without any additional terms or conditions.

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. GotaTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
