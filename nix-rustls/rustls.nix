{ lib
, rustPlatform
, fetchFromGitHub
, buildDylibs ? false
, rename
}:

rustPlatform.buildRustPackage rec {
  pname = "rustls-ffi";
  version = "0.11.0";

  src = fetchFromGitHub {
    owner = "rustls";
    repo = "rustls-ffi";
    rev = "v${version}";
    hash = "sha256-b6rkrI2i/cb7aTqMuq4jdic08EDW0foZlUHQgJMZzRU=";
  };
  cargoLock.lockFile = ./Cargo.lock;
  patches = lib.optionals buildDylibs [ ./rustls-cdylib.patch ];
  postPatch = ''
    cp ${cargoLock.lockFile} Cargo.lock
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
