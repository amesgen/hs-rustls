# hs-rustls — Rustls for Haskell
[![CI](https://github.com/amesgen/hs-rustls/workflows/CI/badge.svg)](https://github.com/amesgen/hs-rustls/actions)
[![Hackage](https://img.shields.io/hackage/v/rustls)](https://hackage.haskell.org/package/rustls)

Haskell bindings for the [Rustls](https://github.com/rustls/rustls) TLS library via [rustls-ffi][].

See [the haddocks](https://hackage.haskell.org/package/rustls/docs/Rustls.html) for documentation.

Also see:

 - [http-client-rustls](/http-client-rustls): Make HTTPS requests using [http-client](https://hackage.haskell.org/package/http-client) and Rustls.

## Development

### With Nix

When developing this library, just drop into a Nix shell.

If you want to depend on this library in another package, you have to make sure to include rustls-ffi as a native dependency. You can do so by depending on the `github:amesgen/hs-rustls?dir=nix-rustls` flake, and then using the `nix-rustls.packages.${system}.default` output.

### Without Nix

#### rustls-ffi

Install [rustls-ffi][] 0.15 either by downloading a pre-built artifact from the release page, or by [building it from source](https://github.com/rustls/rustls-ffi#build-rustls-ffi).

If you installed rustls-ffi globally, you should be good to go. Otherwise, assuming that you installed it to `/path/to/some/dir`, in a `cabal.project.local`, add these lines:

```cabal
extra-include-dirs: /path/to/some/dir/include
extra-lib-dirs:     /path/to/some/dir/lib
```

With this, Cabal should be able to find the rustls-ffi native library.

#### Testing

When running the tests in this repo, you have to have [minica](https://github.com/jsha/minica) and [miniserve](https://github.com/svenstaro/miniserve) installed.

[rustls-ffi]: https://github.com/rustls/rustls-ffi
