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
    owner = "rustls";
    repo = "rustls-ffi";
    rev = "6342e487b11ffe50fff24205e251b978f0502f2f";
    hash = "sha256-QcdWPXgNf2uSw8KRo8j2tgTaQYga4HQ/oDe+J5eDMeI=";
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
