{ lib
, rustPlatform
, fetchFromGitHub
, buildDylibs ? false
, rename
}:

rustPlatform.buildRustPackage rec {
  pname = "rustls-ffi";
  version = "0.13.0";

  src = fetchFromGitHub {
    owner = "amesgen";
    repo = "rustls-ffi";
    rev = "a16b4569ce04fe49e5803d8b834f3279ae9ea03c";
    hash = "sha256-lRKuvxfm2WeY3qRFCUZi3Sj83OZ41wo4WqmKzLmyAMM=";
  };

  cargoHash = "sha256-rHTdX7E3CPdaU5Rj4b/vECpMvKCe9Rbau60QA1hIP28=";

  patches = lib.optionals buildDylibs [ ./rustls-cdylib.patch ];

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
