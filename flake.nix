{
  description = "hanko, a signing service for Android artifacts";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        hanko = pkgs.callPackage ./nix/package.nix { };
        hanko-sign = pkgs.callPackage ./nix/package.nix { pname = "hanko-sign"; };
        default = hanko;
      });

      nixosModules.default = ./nix/module.nix;

      checks = forAllSystems (
        pkgs:
        {
          inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) hanko hanko-sign;
        }
        # Building the test artifacts needs aapt2, which nixpkgs lacks on some systems.
        // pkgs.lib.optionalAttrs (pkgs.lib.meta.availableOn pkgs.stdenv.hostPlatform pkgs.aapt) {
          vm = pkgs.callPackage ./nix/tests/vm.nix { module = ./nix/module.nix; };
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.jdk_headless
            pkgs.bundletool
            pkgs.apksigner
          ]
          ++ pkgs.lib.optional (pkgs.lib.meta.availableOn pkgs.stdenv.hostPlatform pkgs.aapt) pkgs.aapt;
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
