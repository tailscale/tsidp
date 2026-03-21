{
  description = "tsidp - A simple OIDC / OAuth Identity Provider (IdP) server for your tailnet.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs =
    {
      self,
      nixpkgs,
      systems,
    }:
    let
      eachSystem = f: nixpkgs.lib.genAttrs (import systems) (s: f nixpkgs.legacyPackages.${s});
    in
    {
      formatter = eachSystem (pkgs: pkgs.nixfmt-tree);

      packages = eachSystem (pkgs: {
        tsidp = pkgs.callPackage ./nix/package.nix { };

        default = self.packages.${pkgs.system}.tsidp;
      });

      overlays.default = final: prev: {
        tsidp = self.packages.${final.system}.tsidp;
      };

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go_1_24
            pkgs.gopls
          ];
        };
      });

      nixosModules.default = import ./nix/module.nix;
    };
}
