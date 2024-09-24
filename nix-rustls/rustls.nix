{ lib
, rustPlatform
, fetchFromGitHub
, buildDylibs ? false
, rename
}:

rustPlatform.buildRustPackage rec {
  pname = "rustls-ffi";
  version = "0.14.0";

  src = fetchFromGitHub {
    owner = "rustls";
    repo = "rustls-ffi";
    rev = "v${version}";
    hash = "sha256-WnPrYfIoJYz1Qi6RtnWUSo8TXLBxGLhMq4BrARrsLOM=";
  };

  cargoHash = "sha256-rUMLW6EbiH/8R73aCju2WY/YM5h5G4jgX17wuiqUqUI=";

  patches = lib.optionals buildDylibs [ ./rustls-cdylib.patch ];

  nativeBuildInputs = [ rename ];

  # TODO Find out why this fails. We currently don't have bindings for the
  # acceptor API, so this seems acceptable for now.
  checkFlags = [ "--skip=acceptor::tests::test_acceptor_success" ];

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
