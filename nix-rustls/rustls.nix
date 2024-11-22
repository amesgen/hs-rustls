pkgs:

pkgs.rustls-ffi.overrideAttrs (oldAttrs: {
  version = "0.14.1";
  src = oldAttrs.src.overrideAttrs (_: {
    outputHash = "sha256-ZKAyKcKwhnPE6PrfBFjLJKkTlGbdLcmW1EP/xSv2cpM=";
  });
  cargoDeps = oldAttrs.cargoDeps.overrideAttrs (_: {
    outputHash = "sha256-IaOhQfDEgLhGmes0xzhLVym29aP691TY0EXdOIgXEMA=";
  });
})
