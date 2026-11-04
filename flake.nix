{
  description = "MDK development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/d3b13ad75cc492690728f9307e443dec9ef9a20e";

  outputs =
    { nixpkgs, ... }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
    in
    {
      # rustup selects the toolchain pinned in rust-toolchain.toml. OpenSSL and
      # SQLCipher are vendored, so the shell only needs their build tools.
      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = with pkgs; [
          rustup
          just
          cargo-nextest
          cargo-audit
          # Its upstream tests fail in the Nix sandbox; the binary itself works.
          (cargo-llvm-cov.overrideAttrs { doCheck = false; })
          rust-cbindgen
          clang
          gnumake
          cmake
          perl
          pkg-config
          valgrind
          git
          curl
          jq
          python3
          uv
          tamarin-prover
          # TLC lifecycle-model checks run the downloaded tla2tools.jar.
          jre_headless
        ];
        # uv must reuse Nix's Python; its downloaded interpreters do not run on NixOS.
        UV_PYTHON_DOWNLOADS = "never";
        UV_PYTHON = "${pkgs.python3}/bin/python3";
      };
      formatter.x86_64-linux = pkgs.nixfmt;
    };
}
