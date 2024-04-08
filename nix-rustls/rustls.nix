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
    rev = "81e77da7026b141e3e3326190cf01a8bc64b4425";
    hash = "sha256-4Zu/m3FuVTJIjQ7o3le/KZT+78t1T9CS0P+lKxN7NUs=";
  };

  cargoHash = "sha256-z1Uk23wCSikeu0DOZPz2ov2DXPT4oLWx/1JjKCzOqeE=";

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
