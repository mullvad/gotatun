# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [0.1.2] - 2026-01-07
### Changed
- Allow tun devices with packet information on macOS.

### Fixed
- Fix issue where every handshake after 100 received handshake messages triggered a cookie reply.

#### macOS
- Fix dropping privileges not working when running the CLI with `sudo` on macOS. Only the setuid bit
  worked as expected.
- Automatically assign a name in the CLI when passing `utun` as the tunnel name.


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
