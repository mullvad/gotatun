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
      # Support all Linux systems that the nixpkgs flake exposes
      inherit (nixpkgs) lib;
      systems = lib.intersectLists lib.systems.flakeExposed lib.platforms.linux;
      forAllSystems = lib.genAttrs systems;
      nixpkgsFor = forAllSystems (system: nixpkgs.legacyPackages.${system});
    in
    {
      formatter = forAllSystems (system: nixpkgsFor.${system}.nixfmt-tree);

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          rust-bin = rust-overlay.lib.mkRustBin { } pkgs;
          rust-toolchain = rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rust-toolchain
              nixfmt-tree
              deadnix
              statix
            ];
          };
        }
      );

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          rust-bin = rust-overlay.lib.mkRustBin { } pkgs;
          rust-toolchain = rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        {
          default = self.packages.${system}.gotatun;
          gotatun = pkgs.rustPlatform.buildRustPackage {
            pname = "gotatun";
            version = self.shortRev or self.dirtyShortRev or "unknown";
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
            buildNoDefaultFeatures = true;
            nativeBuildInputs = [
              rust-toolchain
            ];
            meta = {
              mainProgram = "gotatun";
              description = "Userspace WireGuard";
              homepage = "https://github.com/mullvad/gotatun";
              license = lib.licenses.bsd3;
              platforms = lib.platforms.linux;
            };
          };
        }
      );
    };
}
