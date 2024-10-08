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

static inline void hs_rustls_connection_get_negotiated_ciphersuite_name(
    const struct rustls_connection *conn, rustls_str *str);
static inline void hs_rustls_connection_get_negotiated_ciphersuite_name(
    const struct rustls_connection *conn, rustls_str *str) {
  *str = rustls_connection_get_negotiated_ciphersuite_name(conn);
}

static inline uint16_t hs_rustls_supported_ciphersuite_protocol_version(
    const struct rustls_supported_ciphersuite *supported_ciphersuite);
static inline uint16_t hs_rustls_supported_ciphersuite_protocol_version(
    const struct rustls_supported_ciphersuite *supported_ciphersuite) {
  return (uint16_t)rustls_supported_ciphersuite_protocol_version(
      supported_ciphersuite);
}

#endif
