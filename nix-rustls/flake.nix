{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rustls-ffi = {
      url = "github:rustls/rustls-ffi/v0.9.1";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, flake-utils, rustls-ffi }:
    let
      rustlsFromPkgs = pkgs: pkgs.callPackage (import ./rustls.nix) {
        src = rustls-ffi;
      };
    in
    { overlays.default = final: prev: { rustls = rustlsFromPkgs prev; }; } //
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
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
        };
        checks = {
          inherit (self.packages.${system})
            rustls
            rustls-with-dylibs;
        };
        devShells.default =
          let
            updatedLockFile = pkgs.writeShellApplication {
              name = "updatedLockFile";
              text = ''
                RUSTLS_FFI=$(mktemp -ud)
                cp --no-preserve=mode,ownership -r ${rustls-ffi} "$RUSTLS_FFI"
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
