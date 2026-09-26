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
        in
        {
          inherit password-jars server;
          default = server;
        }
      );

      nixosModules.default = import ./nix/module.nix { inherit self; };

      checks = forAllSystems (pkgs: {
        inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) password-jars server;
        nixos = pkgs.callPackage ./nix/nixos-test.nix { inherit self; };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.jdk25
            (pkgs.gradle_9.override { java = pkgs.jdk25; })
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
