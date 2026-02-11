# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Add `daita-uapi` feature for configuring DAITA using the UAPI socket. This is disabled by default.

### Fixed
- Fix excessive rekey attempts.
- Fix potential panic due to clocks not being truly monotonic.
- Pad payload to multiple of 16 bytes before encryption in accordance with the WireGuard
  specification.

### Changed
- Make `device::Error` non-exhaustive.
- Move `device::Error` variants specific to the `tun` feature into `tun::tun_async_device::Error`.
- Rename DAITA-concept of "padding packets" to "decoy packets"


## [0.2.0] - 2026-01-13
### Changed
- Rework `device` API.
- Rename `DeviceHandle` to `Device` (and make the old `Device` type private).
- Replace `Device` constructor with `DeviceBuilder`.
- Expose `Device` configuration through `Device::write` and `Device::read`.
- Rename `device::api::{ApiServer, ApiClient}` to `device::uapi::{UapiServer, UapiClient}`.
- Hide `daita` implementation behind feature gate.
- Replace crate `ip_network` with the more popular `ipnetwork` in public API.
- Don't change ownership of `/var/run/wireguard` when dropping privileges in the CLI.
- Re-export `maybenot` crate.

### Fixed
- Update daemonize to `0.5` in CLI to resolve deprecation warning.
- Report correct last handshake in UAPI.

### Removed
- Remove unused `device::Error` variants.
- Remove `AllowedIp` and `AllowedIps` type from public API.
- Remove `drop_privileges` module from public API.


## [0.1.2] - 2026-01-07
### Changed
- Allow tun devices with packet information on macOS.

### Fixed
- Fix issue where every handshake after 100 received handshake messages triggered a cookie reply.

#### macOS
- Fix dropping privileges not working when running the CLI with `sudo` on macOS. Only the setuid bit
  worked as expected.
- Automatically assign a name in the CLI when passing `utun` as the tunnel name.
- Fix bad file descriptor error when running CLI daemonized.


## [0.1.1] - 2025-12-23
### Added
- Add nix flake for building `gotatun`.
- Add nix devshell.

### Changed
- Rename `gotatun-cli` binary to `gotatun`.
- Upgrade `tun` crate to 0.8.5.
- Disable `wintun.dll` verification to speed up startup.

### Fixed
- Handle SIGINT and SIGTERM in cli


## [0.1.0] - 2025-11-06
Create initial release of GotaTun, a userspace [WireGuard]<sup>®</sup> implementation based on [Boringtun] v.0.6.0.

### Added
- Add DAITA V3.
- Add multihop.
- Add support for Android.

### Changed
- Replace custom event loop with tokio.

### Removed
- Remove FFI bindings.

[Boringtun]: https://github.com/cloudflare/boringtun
[WireGuard]: https://www.wireguard.com/
