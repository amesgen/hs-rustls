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
    rev = "fe0415310112c441c2673cc4a6eb7243c456af12";
    hash = "sha256-sQo/K51BcZfHEEg4lcQh2/ZZ8VE8RFHuhuyN5gkxKY0=";
  };

  cargoHash = "sha256-i84i9XxqDj+KHgklHNYrN8BUmXn+bZZLzbr2de1aGZk=";

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
