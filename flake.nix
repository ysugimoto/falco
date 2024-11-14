{
  description = "Falco flake";
  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";
  inputs.gomod2nix = {
    url = "github:tweag/gomod2nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.flake-parts.url = "github:hercules-ci/flake-parts";
  outputs = inputs@{ self, nixpkgs, gomod2nix, flake-parts }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems =
        [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { system, ... }:
        let
          pkgs = import self.inputs.nixpkgs {
            inherit system;
            overlays = [ gomod2nix.overlays.default ];
          };
          name = "falco";
          version = "1.11.2";
          stable-source = pkgs.fetchFromGitHub {
            owner = "ysugimoto";
            repo = name;
            rev = "refs/tags/v${version}";
            sha256 = "sha256-2jmzdjahOB/iEF5AzusA5PMDT1O1JKhpiirnSRN2j3Q=";
          };
        in {
          _module.args.pkgs = pkgs;
          packages = rec {
            setup = let pwd = toString ./.;
            in pkgs.writeShellApplication {
              name = "setup";
              runtimeInputs = [ pkgs.git pkgs.gomod2nix ];
              text = ''
                ROOT=$(pwd)
                echo "$ROOT"
                TMP=$(mktemp -d)
                git clone https://github.com/ysugimoto/falco -b "v''${1:-${version}}" "$TMP"/falco
                cd "$TMP"/falco
                gomod2nix
                cd "$ROOT"
                cp "$TMP"/falco/gomod2nix.toml nix/gomod2nix."v''${1:-${version}}".toml
              '';
            };
            stable = pkgs.buildGoApplication {
              pname = name;
              version = version;
              src = stable-source;
              modules = ./nix/gomod2nix.v${version}.toml;
            };
            unstable = pkgs.buildGoApplication {
              pname = name;
              version = "unstable";
              src = ./.;
              modules = ./gomod2nix.toml;
            };
            default = stable;
          };
        };
    };
}
