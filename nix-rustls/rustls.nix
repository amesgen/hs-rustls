{ fenix
, naersk

, lib
, stdenv

, runCommand
, applyPatches

, src
, cargoLock ? ./Cargo.lock

, buildDylibs ? false
, staticMusl ? stdenv.targetPlatform.isMusl

, rename
}:
let
  inherit (stdenv) system;
  naersk-lib =
    let
      fenix-packages = fenix.packages.${system};
      toolchain =
        fenix-packages.combine ([
          fenix-packages.stable.rustc
          fenix-packages.stable.cargo
          fenix-packages.stable.rust-std
        ] ++ lib.optional staticMusl [
          fenix-packages.targets.x86_64-unknown-linux-musl.stable.rust-std
        ]);
    in
    naersk.lib.${system}.override {
      cargo = toolchain;
      rustc = toolchain;
    };
in
naersk-lib.buildPackage ({
  pname = "rustls-ffi";
  version = "0.9.1";

  # TODO remove IFD
  src = applyPatches {
    name = "rustls-src";
    inherit src;
    patches = lib.optionals buildDylibs [ ./rustls-cdylib.patch ];
    postPatch = ''
      cp ${cargoLock} Cargo.lock
    '';
  };

  copyLibs = true;

  nativeBuildInputs = [ rename ];

  postInstall = ''
    rm -rf $out/bin
    mkdir -p $out/include
    cp src/rustls.h $out/include
    cd $out/lib
    rm -f *.rlib
    rename 's/librustls_ffi/librustls/g' *
  '';

  meta = {
    description = "Bindings to Rustls, a modern TLS library written in Rust";
    homepage = "https://github.com/rustls/rustls-ffi";
    license = with lib.licenses; [ asl20 mit isc ];
    platforms = lib.platforms.unix;
  };
} // lib.optionalAttrs staticMusl {
  CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
})
