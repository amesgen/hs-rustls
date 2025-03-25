{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    let
      rustlsFromPkgs = import ./rustls.nix;
    in
    {
      overlays.default = _: prev: {
        # use prev instead once rustls-ffi in nixpkgs is stable
        rustls-ffi = rustlsFromPkgs nixpkgs.legacyPackages.${prev.system};
        haskell-nix = prev.haskell-nix or { } // {
          extraPkgconfigMappings = prev.haskell-nix.extraPkgconfigMappings or { } // {
            "rustls" = [ "rustls-ffi" ];
          };
        };
      };
    } //
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        rustls = rustlsFromPkgs pkgs;
      in
      {
        packages = {
          default = rustls;
          inherit rustls;
          rustls-static = rustlsFromPkgs pkgs.pkgsStatic;
          ci = pkgs.linkFarm "nix-rustls-ci" {
            inherit (self.packages.${system}) rustls;
          };
        };
      });
}
