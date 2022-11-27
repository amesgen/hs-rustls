{
  inputs = {
    haskellNix.url = "github:input-output-hk/haskell.nix";
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    nur.url = "github:nix-community/nur";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
    nix-rustls = {
      url = "path:./nix-rustls";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };
  outputs = { self, nixpkgs, nur, flake-utils, haskellNix, pre-commit-hooks, nix-rustls }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          inherit (haskellNix) config;
          overlays = [
            haskellNix.overlay
            nur.overlay
            (_: prev: { inherit (pkgs.nur.repos.amesgen) ormolu cabal-docspec; })
            nix-rustls.overlays.default
            # ghci(d) needs dynamic libs
            (_: prev: { rustls = prev.rustls.override (_: { buildDylibs = true; }); })
          ];
        };
        inherit (pkgs) lib haskell-nix;
        inherit (haskell-nix) haskellLib;
        projectPackages = [ "rustls" "http-client-rustls" ];
        hsPkgs = haskell-nix.cabalProject {
          src = ./.;
          compiler-nix-name = "ghc925";
          modules = [
            { packages = lib.genAttrs projectPackages (_: { ghcOptions = [ "-Werror" ]; }); }
            {
              packages.rustls.components.tests.tasty.preCheck = ''
                export PATH=${lib.makeBinPath [ pkgs.minica ]}:$PATH
              '';
              packages.http-client-rustls.components.tests.tasty.preCheck = ''
                export PATH=${lib.makeBinPath [ pkgs.minica pkgs.miniserve ]}:$PATH
              '';
            }
          ];
        };
      in
      {
        packages = { inherit (pkgs) rustls; };
        checks = flake-utils.lib.flattenTree
          (haskellLib.collectChecks haskellLib.isProjectPackage hsPkgs) // {
          pre-commit-check = pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks.ormolu.enable = true;
            tools = { inherit (pkgs) ormolu; };
          };
        };
        devShells.default = hsPkgs.shellFor {
          tools = { cabal = { }; };
          exactDeps = true;
          buildInputs = [
            pkgs.minica
            pkgs.miniserve
            pkgs.cabal-docspec
            pkgs.ormolu
          ];
          LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.rustls ];
          withHoogle = false;
          inherit (self.checks.${system}.pre-commit-check) shellHook;
        };
      });
  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
  };
}
