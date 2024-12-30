# Revision history for rustls

## 0.2.1.0 -- 30.12.2024

 * Add `use-pkg-config` flag (enabled by default).
 * Use rustls-ffi 0.14.1.

## 0.2.0.0 -- 24.09.2024

 * Use rustls-ffi 0.14.0.
    * New feature: accessing the OS certificate store via
      `rustls-platform-verifier`.
    * Cipher suites are now tied to a specific cryptography provider.
    * TLS versions are now automatically derived from the specified cipher
      suites.
 * Support GHC 9.10

## 0.1.0.0 -- 06.04.2024

 * Use rustls-ffi 0.13.0, including new functionality (like recovactions)
 * Only support GHC >= 9.2
 * `Backend` is now a record instead of a type class

## 0.0.1.0 -- 12.03.2022

 * Use rustls-ffi 0.9.2
 * Use `ConstPtr` on GHC 9.6.1
 * Report `LogCallback` exceptions via uncaught exception handler

## 0.0.0.0 -- 24.06.2022

 * Initial release
