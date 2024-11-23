# hs-rustls — Rustls for Haskell
[![CI](https://github.com/amesgen/hs-rustls/workflows/CI/badge.svg)](https://github.com/amesgen/hs-rustls/actions)
[![Hackage](https://img.shields.io/hackage/v/rustls)](https://hackage.haskell.org/package/rustls)

Haskell bindings for the [Rustls](https://github.com/rustls/rustls) TLS library via [rustls-ffi](https://github.com/rustls/rustls-ffi).

See [the haddocks](https://hackage.haskell.org/package/rustls/docs/Rustls.html) for documentation.

Also see:

 - [http-client-rustls](/http-client-rustls): Make HTTPS requests using [http-client](https://hackage.haskell.org/package/http-client) and Rustls.

## Development

### With Nix

When developing this library, just drop into a Nix shell.

If you want to depend on this library in another package, you have to make sure to include rustls-ffi as a native dependency. You can do so by depending on the `github:amesgen/hs-rustls?dir=nix-rustls` flake, and then using the `nix-rustls.packages.${system}.default` output.

### Without Nix

#### rustls-ffi

Make sure to have [Cargo](https://doc.rust-lang.org/stable/cargo/getting-started/installation.html) installed. Then, clone and install rustls-ffi:

```bash
git clone https://github.com/rustls/rustls-ffi -b v0.14.1
cd rustls-ffi
make DESTDIR=/path/to/some/dir install
```

Then, in a `cabal.project.local`, add these lines:

```cabal
extra-include-dirs: /path/to/some/dir/include
extra-lib-dirs:     /path/to/some/dir/lib
```

With this, Cabal should be able to find the rustls-ffi native library.

> Note: This process might become less manual if sth like [haskell/cabal#7906](https://github.com/haskell/cabal/issues/7906) lands in Cabal.

#### Testing

When running the tests in this repo, you have to have [minica](https://github.com/jsha/minica) and [miniserve](https://github.com/svenstaro/miniserve) installed.
