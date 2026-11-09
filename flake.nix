{
  description = "MDK development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/d3b13ad75cc492690728f9307e443dec9ef9a20e";

  outputs =
    { nixpkgs, ... }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      environment = pkgs.buildFHSEnv {
        name = "mdk-dev";
        includeClosures = true;
        extraOutputsToInstall = [ "dev" ];
        targetPkgs =
          _: with pkgs; [
            rustup
            clang
            gnumake
            cmake
            perl
            pkg-config
            valgrind
            git
            cacert
            just
            curl
            jq
            ripgrep
            python3
            coreutils
            findutils
            gnused
            gnugrep
            gnutar
            gzip
            bzip2
            unzip
            zip
            zstd
            cargo-nextest
            cargo-audit
            # Its upstream tests fail in the Nix sandbox; the binary itself works.
            (cargo-llvm-cov.overrideAttrs { doCheck = false; })
            rust-cbindgen
            uv
            tamarin-prover
            # TLC lifecycle-model checks run the downloaded tla2tools.jar.
            jre_headless
          ];
        profile = ''
          export CC=${pkgs.clang}/bin/clang
          export CXX=${pkgs.clang}/bin/clang++
          export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
          export CARGO_HTTP_CAINFO="$SSL_CERT_FILE"
          export PATH=${pkgs.rustup}/bin:$PATH
          # Keep uv on Nix's Python rather than downloading an interpreter.
          export UV_PYTHON_DOWNLOADS=never
          export UV_PYTHON=${pkgs.python3}/bin/python3
        '';
        runScript = pkgs.writeShellScript "development-shell" ''
          if [ "$#" -eq 0 ]; then
            exec ${pkgs.bashInteractive}/bin/bash --noprofile --norc -i
          fi
          exec "$@"
        '';
      };
    in
    {
      packages.x86_64-linux.default = environment;
      devShells.x86_64-linux.default = environment.env;
      apps.x86_64-linux.default = {
        type = "app";
        program = pkgs.lib.getExe environment;
        meta.description = "Run a command in the MDK development environment";
      };
      formatter.x86_64-linux = pkgs.nixfmt;
    };
}
