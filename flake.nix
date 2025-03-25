{
  inputs = {
    haskellNix = {
      url = "github:input-output-hk/haskell.nix";
      inputs.stackage.url = "github:input-output-hk/empty-flake";
    };
    nixpkgs.follows = "haskellNix/nixpkgs-unstable";
    nur.url = "github:nix-community/nur";
    flake-utils.url = "github:numtide/flake-utils";
    get-flake.url = "github:ursi/get-flake";
    pre-commit-hooks.url = "github:cachix/git-hooks.nix";
  };
  outputs = inputs@{ self, nixpkgs, flake-utils, get-flake, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          inherit (inputs.haskellNix) config;
          overlays = [
            inputs.haskellNix.overlay
            inputs.nur.overlays.default
            (_: prev: {
              inherit (prev.nur.repos.amesgen)
                ormolu
                cabal-docspec
                cabal-gild
                ;
            })
            (get-flake ./nix-rustls).overlays.default
          ];
        };
        inherit (pkgs) lib haskell-nix;
        inherit (haskell-nix) haskellLib;
        projectPackages = [ "rustls" "http-client-rustls" ];
        hsPkgs = haskell-nix.cabalProject {
          src = ./.;
          compiler-nix-name = "ghc912";
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
        packages = {
          inherit (pkgs) rustls-ffi;
          ci = pkgs.linkFarmFromDrvs "hs-rustls-ci" (lib.attrValues self.checks.${system});
        };
        checks = flake-utils.lib.flattenTree
          (haskellLib.collectChecks haskellLib.isProjectPackage hsPkgs) // {
          pre-commit-check = inputs.pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              ormolu.enable = true;
              cabal-gild.enable = true;
              nixpkgs-fmt.enable = true;
              deadnix.enable = true;
            };
            tools = { inherit (pkgs) ormolu cabal-gild; };
          };
          doctests = pkgs.runCommandCC "test-cabal-docspec"
            {
              nativeBuildInputs = [
                pkgs.cabal-docspec
                (hsPkgs.ghcWithPackages
                  (ps: lib.filter (p: p ? components.library)
                    (lib.attrValues (haskellLib.selectProjectPackages ps))))
              ];
            } ''
            export CABAL_DIR=$(mktemp -d)
            touch $CABAL_DIR/config $out
            cabal-docspec --no-cabal-plan $(find ${./.} -name '*.cabal')
          '';
        };
        devShells.default = hsPkgs.shellFor {
          buildInputs = [
            pkgs.minica
            pkgs.miniserve
            pkgs.cabal-install
            pkgs.cabal-docspec
          ] ++ self.checks.${system}.pre-commit-check.enabledPackages;
          withHoogle = false;
          inherit (self.checks.${system}.pre-commit-check) shellHook;
        };
      });
  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
      "https://cache.zw3rk.com"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "loony-tools:pr9m4BkM/5/eSTZlkQyRt57Jz7OMBxNSUiMC4FkcNfk="
    ];
  };
}
