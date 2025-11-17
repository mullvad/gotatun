{
  description = "GotaTun: A userspace implemenation of WireGuard written in Rust.";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      gotatun-package =
        {
          lib,
          rustPlatform,
          rust-toolchain,
        }:
        rustPlatform.buildRustPackage {
          pname = "gotatun";
          version = self.shortRev or self.dirtyShortRev or "unknown";
          meta = {
            mainProgram = "gotatun";
            description = "Userspace WireGuard";
            homepage = "https://github.com/mullvad/gotatun";
            license = lib.licenses.bsd3;
            platforms = lib.platforms.linux;
          };
          buildNoDefaultFeatures = true;
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./gotatun
              ./gotatun-cli
              ./Cargo.toml
              ./Cargo.lock
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          strictDeps = true;
          nativeBuildInputs = [
            rust-toolchain
          ];
        };

      # Support all Linux systems that the nixpkgs flake exposes
      inherit (nixpkgs) lib;
      systems = lib.intersectLists lib.systems.flakeExposed lib.platforms.linux;
      forAllSystems = lib.genAttrs systems;
      nixpkgsFor = forAllSystems (system: nixpkgs.legacyPackages.${system});
    in
    {
      checks = forAllSystems (system: {
        inherit (self.packages.${system}) gotatun;
      });

      formatter = forAllSystems (system: nixpkgsFor.${system}.nixfmt-rfc-style);

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          rust-bin = rust-overlay.lib.mkRustBin { } pkgs;
        in
        {
          default = pkgs.mkShell {
            packages = [
              (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
            ];
          };
        }
      );

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          rust-bin = rust-overlay.lib.mkRustBin { } pkgs;
          rust-toolchain-base = rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          gotatun = nixpkgsFor.${system}.callPackage gotatun-package {
            rust-toolchain = rust-toolchain-base;
          };
        in
        {
          default = gotatun;
        }
      );

      overlays.default = final: _: {
        gotatun = final.callPackage gotatun-package { };
      };
    };
}
