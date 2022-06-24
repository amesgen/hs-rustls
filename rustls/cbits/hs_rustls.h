#ifndef HS_RUSTLS_H
#define HS_RUSTLS_H

#include "rustls.h"

static inline void hs_rustls_version(rustls_str *str);
static inline void hs_rustls_version(rustls_str *str) {
  *str = rustls_version();
}

static inline void hs_rustls_supported_ciphersuite_get_name(
    const struct rustls_supported_ciphersuite *supported_ciphersuite,
    rustls_str *str);
static inline void hs_rustls_supported_ciphersuite_get_name(
    const struct rustls_supported_ciphersuite *supported_ciphersuite,
    rustls_str *str) {
  *str = rustls_supported_ciphersuite_get_name(supported_ciphersuite);
}

#endif
