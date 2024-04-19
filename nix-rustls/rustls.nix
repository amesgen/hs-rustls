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
    rev = "819ba4bcd3d9fbece2e6b1b3b3d92f025df3e7fb";
    hash = "sha256-Uq0FNJ6/cDbdOlxtlw6Gecng8xYy+IFU6QhaFG20j2A=";
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
