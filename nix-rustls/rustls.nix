{ lib
, rustPlatform

, src
, cargoLock ? ./Cargo.lock

, buildDylibs ? false

, rename
}:

rustPlatform.buildRustPackage {
  pname = "rustls-ffi";
  version = "0.9.1";

  inherit src;
  cargoLock.lockFile = cargoLock;
  patches = lib.optionals buildDylibs [ ./rustls-cdylib.patch ];
  postPatch = ''
    cp ${cargoLock} Cargo.lock
  '';

  nativeBuildInputs = [ rename ];

  postInstall = ''
    mkdir -p $out/include
    cp src/rustls.h $out/include
    cd $out/lib
    rename 's/librustls_ffi/librustls/g' *
  '';

  meta = {
    description = "Bindings to Rustls, a modern TLS library written in Rust";
    homepage = "https://github.com/rustls/rustls-ffi";
    license = with lib.licenses; [ asl20 mit isc ];
    platforms = lib.platforms.unix;
  };
}
