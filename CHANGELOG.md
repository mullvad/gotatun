# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Add nix flake for building `gotatun`.
- Add nix devshell.
- Add `mimalloc` as an optional, alternative memory allocator.

### Changed
- Rename `gotatun-cli` binary to `gotatun`.


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
