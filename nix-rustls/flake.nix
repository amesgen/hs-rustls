{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rustls-ffi = {
      url = "github:rustls/rustls-ffi/v0.9.1";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, flake-utils, fenix, naersk, rustls-ffi }:
    let
      rustlsFromPkgs = pkgs: pkgs.callPackage (import ./rustls.nix) {
        src = rustls-ffi;
        inherit fenix naersk;
      };
    in
    { overlays.default = final: prev: { rustls = rustlsFromPkgs prev; }; } //
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        rustls = rustlsFromPkgs pkgs;
      in
      {
        packages.default = rustls;
        checks = {
          inherit rustls;
          rustls-with-dylibs = rustls.override (_: { buildDylibs = true; });
          rustls-musl = rustls.override (_: { staticMusl = true; });
        };
        devShells.default =
          let
            updatedLockFile = pkgs.writeShellScriptBin "updatedLockFile" ''
              RUSTLS_FFI=$(mktemp -ud)
              cp --no-preserve=mode,ownership -r ${rustls-ffi} $RUSTLS_FFI
              ${pkgs.cargo}/bin/cargo update --manifest-path $RUSTLS_FFI/Cargo.toml
              cat $RUSTLS_FFI/Cargo.lock
              rm -r $RUSTLS_FFI
            '';
          in
          pkgs.mkShell {
            packages = [ updatedLockFile ];
          };
      });
}
