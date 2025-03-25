pkgs:

pkgs.rustls-ffi.overrideAttrs (finalAttrs: oldAttrs: {
  version = "0.15.0";
  src = oldAttrs.src.overrideAttrs (_: {
    outputHash = "sha256-m92kWH+J8wuGmI0msrp2aginY1K51iqgi3+u4ncmfts=";
  });
  cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
    src = finalAttrs.src;
    name = "${finalAttrs.pname}-${finalAttrs.version}";
    hash = "sha256-gqc6en59QQpD14hOgRuGEPWLvrkyGn9tPR9vQmRAxIg=";
  };
})
