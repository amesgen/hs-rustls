pkgs:

pkgs.rustls-ffi.overrideAttrs (oldAttrs: {
  version = "0.14.0";
  src = oldAttrs.src.overrideAttrs (_: {
    outputHash = "sha256-WnPrYfIoJYz1Qi6RtnWUSo8TXLBxGLhMq4BrARrsLOM=";
  });
  cargoDeps = oldAttrs.cargoDeps.overrideAttrs (_: {
    outputHash = "sha256-rUMLW6EbiH/8R73aCju2WY/YM5h5G4jgX17wuiqUqUI=";
  });
})
