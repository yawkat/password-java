{
  description = "password-java: encrypted password database server and client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          password-jars = pkgs.callPackage ./nix/package.nix { };
          server = pkgs.callPackage ./nix/server.nix { inherit password-jars; };
          # the desktop app only exists where password-jars builds it (x86_64-linux)
          app = lib.optionalAttrs password-jars.withApp {
            app = pkgs.callPackage ./nix/app.nix { inherit password-jars; };
          };
        in
        {
          inherit password-jars server;
          default = app.app or server;
        }
        // app
      );

      nixosModules.default = import ./nix/module.nix { inherit self; };

      checks = forAllSystems (
        pkgs:
        let
          packages = self.packages.${pkgs.stdenv.hostPlatform.system};
        in
        {
          inherit (packages) password-jars server;
          nixos = pkgs.callPackage ./nix/nixos-test.nix { inherit self; };
        }
        // lib.optionalAttrs (packages ? app) { inherit (packages) app; }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.jdk25
            self.packages.${pkgs.stdenv.hostPlatform.system}.password-jars.gradle
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
