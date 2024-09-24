{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    let
      rustlsFromPkgs = pkgs: pkgs.callPackage (import ./rustls.nix) { };
    in
    { overlays.default = _: prev: { rustls = rustlsFromPkgs prev; }; } //
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        rustls = rustlsFromPkgs pkgs;
      in
      {
        packages = {
          default = rustls;
          inherit rustls;
          rustls-with-dylibs = rustls.override { buildDylibs = true; };
          rustls-static = rustlsFromPkgs pkgs.pkgsStatic;
          ci = pkgs.linkFarm "nix-rustls-ci" {
            inherit (self.packages.${system})
              rustls
              rustls-with-dylibs;
          };
        };
        devShells.default =
          let
            updatedLockFile = pkgs.writeShellApplication {
              name = "updatedLockFile";
              text = ''
                RUSTLS_FFI=$(mktemp -ud)
                cp --no-preserve=mode,ownership -r ${rustls.src} "$RUSTLS_FFI"
                rm -f "$RUSTLS_FFI/Cargo.lock"
                ${pkgs.cargo}/bin/cargo update --manifest-path "$RUSTLS_FFI/Cargo.toml"
                cat "$RUSTLS_FFI/Cargo.lock"
                rm -r "$RUSTLS_FFI"
              '';
            };
          in
          pkgs.mkShell {
            packages = [ updatedLockFile ];
          };
      });
}
