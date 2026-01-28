{
  description = "Flake for Marmot Development Kit (MDK) Rust project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        rust = pkgs.rust-bin.stable.latest.default;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rust
            cargo
            openssl
            pkg-config
            sqlite
            just
          ];

          shellHook = ''
            echo "✅ MDK dev shell loaded. Use 'cargo build', 'cargo test', or 'just' for development."
          '';
        };
      }
    );
}

