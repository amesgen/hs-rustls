-- | Internal module, not subject to PVP.
--
-- Functionality without bindings ATM (not exhaustive):
--
--  - Certain client verifier parts
--  - Session persistence
--  - ECH
--  - SSLKEYLOG
--  - FIPS
--  - Explicit TLS 1.3 key updates
--  - Certified key consistency check
module Rustls.Internal.FFI
  ( ConstPtr (..),
    ConstCString,

    -- * Client

    -- ** Config
    ClientConfig,
    ClientConfigBuilder,
    clientConfigBuilderNewCustom,
    clientConfigBuilderFree,
    clientConfigBuilderBuild,
    clientConfigFree,
    clientConfigBuilderSetALPNProtocols,
    clientConfigBuilderSetEnableSNI,
    clientConfigBuilderSetCertifiedKey,
    WebPkiServerCertVerifierBuilder,
    ServerCertVerifier,
    webPkiServerCertVerifierBuilderNewWithProvider,
    webPkiServerCertVerifierBuilderAddCrl,
    webPkiServerCertVerifierEnforceRevocationExpiry,
    webPkiServerCertVerifierBuilderFree,
    webPkiServerCertVerifierBuilderBuild,
    platformServerCertVerifierWithProvider,
    serverCertVerifierFree,
    clientConfigBuilderSetServerVerifier,

    -- ** Connection
    clientConnectionNew,
    serverConnectionNew,

    -- * Server

    -- ** Config
    ServerConfig,
    ServerConfigBuilder,
    serverConfigBuilderNewCustom,
    serverConfigBuilderFree,
    serverConfigBuilderBuild,
    serverConfigFree,
    serverConfigBuilderSetALPNProtocols,
    serverConfigBuilderSetIgnoreClientOrder,
    serverConfigBuilderSetCertifiedKeys,
    WebPkiClientCertVerifierBuilder,
    ClientCertVerifier,
    webPkiClientCertVerifierBuilderNewWithProvider,
    webPkiClientCertVerifierBuilderAddCrl,
    webPkiClientCertVerifierBuilderAllowUnauthenticated,
    webPkiClientCertVerifierBuilderFree,
    webPkiClientCertVerifierBuilderBuild,
    clientCertVerifierFree,
    serverConfigBuilderSetClientVerifier,

    -- * Certificate stuff
    CertifiedKey,
    certifiedKeyBuild,
    certifiedKeyFree,
    Certificate,
    certificateGetDER,

    -- * Connection
    Connection,
    connectionFree,

    -- ** Read/write

    -- *** Read
    ReadCallback,
    mkReadCallback,
    connectionWantsRead,
    connectionRead,
    connectionReadTls,

    -- *** Write
    WriteCallback,
    mkWriteCallback,
    connectionWantsWrite,
    connectionWrite,
    connectionWriteTls,

    -- ** Misc
    connectionProcessNewPackets,
    connectionIsHandshaking,
    connectionSendCloseNotify,
    connectionSetBufferLimit,
    connectionGetALPNProtocol,
    connectionGetProtocolVersion,
    connectionGetNegotiatedCipherSuite,
    connectionGetNegotiatedCipherSuiteName,
    connectionGetNegotiatedKeyExchangeGroup,
    connectionGetNegotiatedKeyExchangeGroupName,
    connectionHandshakeKind,
    handshakeKindStr,
    serverConnectionGetSNIHostname,
    connectionGetPeerCertificate,

    -- ** Logging
    connectionSetLogCallback,
    LogCallback,
    mkLogCallback,
    LogParams (..),
    LogLevel (..),

    -- * Misc
    Str (..),
    SliceBytes (..),
    hsVersion,
    Userdata,

    -- ** 'Result'
    Result (..),
    resultIsCertError,
    errorMsg,

    -- *** Some values
    resultOk,
    resultInsufficientSize,

    -- ** 'IOResult'
    IOResult (..),
    ioResultOk,
    ioResultErr,

    -- ** TLS params
    SupportedCipherSuite,
    supportedCipherSuiteGetSuite,
    hsSupportedCipherSuiteGetName,
    hsSupportedCiphersuiteProtocolVersion,
    TLSVersion (..),
    pattern TLS12,
    pattern TLS13,

    -- ** Crypto provider
    CryptoProvider,
    CryptoProviderBuilder,
    cryptoProviderBuilderNewFromDefault,
    cryptoProviderBuilderNewWithBase,
    cryptoProviderBuilderSetCipherSuites,
    cryptoProviderBuilderBuild,
    cryptoProviderBuilderFree,
    cryptoProviderFree,
    cryptoProviderCiphersuitesLen,
    cryptoProviderCiphersuitesGet,

    -- ** Root cert store
    RootCertStoreBuilder,
    RootCertStore,
    rootCertStoreBuilderNew,
    rootCertStoreBuilderAddPem,
    rootCertStoreBuilderLoadRootsFromFile,
    rootCertStoreBuilderFree,
    rootCertStoreBuilderBuild,
    rootCertStoreFree,
  )
where

import Data.Word
import Foreign
import Foreign.C
import Foreign.Storable.Generic
import GHC.Generics (Generic)

#if MIN_VERSION_base(4,18,0)
import Foreign.C.ConstPtr
#else
newtype ConstPtr a = ConstPtr {unConstPtr :: Ptr a}
  deriving newtype (Show, Eq, Storable)
#endif

type ConstCString = ConstPtr CChar

-- Misc

data {-# CTYPE "rustls.h" "rustls_str" #-} Str = Str CString CSize
  deriving stock (Generic)
  deriving anyclass (GStorable)

data {-# CTYPE "rustls.h" "rustls_slice_bytes" #-} SliceBytes = SliceBytes (Ptr Word8) CSize
  deriving stock (Generic)
  deriving anyclass (GStorable)

foreign import capi unsafe "hs_rustls.h hs_rustls_version"
  hsVersion :: Ptr Str -> IO ()

newtype {-# CTYPE "rustls.h" "rustls_result" #-} Result = Result Word32
  deriving stock (Show, Eq, Ord)

foreign import capi "rustls.h value RUSTLS_RESULT_OK"
  resultOk :: Result

foreign import capi "rustls.h value RUSTLS_RESULT_INSUFFICIENT_SIZE"
  resultInsufficientSize :: Result

foreign import capi unsafe "rustls.h rustls_result_is_cert_error"
  resultIsCertError :: Result -> CBool

foreign import capi unsafe "rustls.h rustls_error"
  errorMsg :: Result -> CString -> CSize -> Ptr CSize -> IO ()

newtype {-# CTYPE "rustls.h" "rustls_io_result" #-} IOResult = IOResult CInt
  deriving stock (Eq)

ioResultOk :: IOResult
ioResultOk = IOResult 0

ioResultErr :: IOResult
ioResultErr = IOResult 1

-- | (Unused) userdata.
data Userdata

-- Client

data {-# CTYPE "rustls.h" "rustls_client_config" #-} ClientConfig

data {-# CTYPE "rustls.h" "rustls_client_config_builder" #-} ClientConfigBuilder

foreign import capi unsafe "rustls.h rustls_client_config_builder_new_custom"
  clientConfigBuilderNewCustom ::
    ConstPtr CryptoProvider ->
    ConstPtr TLSVersion ->
    CSize ->
    Ptr (Ptr ClientConfigBuilder) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_free"
  clientConfigBuilderFree :: Ptr ClientConfigBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_build"
  clientConfigBuilderBuild ::
    Ptr ClientConfigBuilder -> Ptr (ConstPtr ClientConfig) -> IO Result

foreign import capi unsafe "rustls.h &rustls_client_config_free"
  clientConfigFree :: FinalizerPtr ClientConfig

foreign import capi unsafe "rustls.h rustls_client_connection_new"
  clientConnectionNew ::
    ConstPtr ClientConfig ->
    -- | Hostname.
    ConstCString ->
    Ptr (Ptr Connection) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_alpn_protocols"
  clientConfigBuilderSetALPNProtocols ::
    Ptr ClientConfigBuilder -> ConstPtr SliceBytes -> CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_enable_sni"
  clientConfigBuilderSetEnableSNI :: Ptr ClientConfigBuilder -> CBool -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_certified_key"
  clientConfigBuilderSetCertifiedKey ::
    Ptr ClientConfigBuilder -> ConstPtr (ConstPtr CertifiedKey) -> CSize -> IO Result

data
  {-# CTYPE "rustls.h" "rustls_web_pki_server_cert_verifier_builder" #-}
  WebPkiServerCertVerifierBuilder

data
  {-# CTYPE "rustls.h" "rustls_server_cert_verifier" #-}
  ServerCertVerifier

foreign import capi unsafe "rustls.h rustls_web_pki_server_cert_verifier_builder_new_with_provider"
  webPkiServerCertVerifierBuilderNewWithProvider ::
    ConstPtr CryptoProvider ->
    ConstPtr RootCertStore ->
    IO (Ptr WebPkiServerCertVerifierBuilder)

foreign import capi unsafe "rustls.h rustls_web_pki_server_cert_verifier_builder_add_crl"
  webPkiServerCertVerifierBuilderAddCrl ::
    Ptr WebPkiServerCertVerifierBuilder -> ConstPtr Word8 -> CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_web_pki_server_cert_verifier_enforce_revocation_expiry"
  webPkiServerCertVerifierEnforceRevocationExpiry ::
    Ptr WebPkiServerCertVerifierBuilder -> IO Result

foreign import capi unsafe "rustls.h rustls_web_pki_server_cert_verifier_builder_free"
  webPkiServerCertVerifierBuilderFree ::
    Ptr WebPkiServerCertVerifierBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_web_pki_server_cert_verifier_builder_build"
  webPkiServerCertVerifierBuilderBuild ::
    Ptr WebPkiServerCertVerifierBuilder -> Ptr (Ptr ServerCertVerifier) -> IO Result

foreign import capi unsafe "rustls.h rustls_platform_server_cert_verifier_with_provider"
  platformServerCertVerifierWithProvider ::
    ConstPtr CryptoProvider -> IO (Ptr ServerCertVerifier)

foreign import capi unsafe "rustls.h rustls_server_cert_verifier_free"
  serverCertVerifierFree :: Ptr ServerCertVerifier -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_server_verifier"
  clientConfigBuilderSetServerVerifier ::
    Ptr ClientConfigBuilder -> ConstPtr ServerCertVerifier -> IO ()

-- Server

data {-# CTYPE "rustls.h" "rustls_server_config" #-} ServerConfig

data {-# CTYPE "rustls.h" "rustls_server_config_builder" #-} ServerConfigBuilder

foreign import capi unsafe "rustls.h rustls_server_config_builder_new_custom"
  serverConfigBuilderNewCustom ::
    ConstPtr CryptoProvider ->
    ConstPtr TLSVersion ->
    CSize ->
    Ptr (Ptr ServerConfigBuilder) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_free"
  serverConfigBuilderFree :: Ptr ServerConfigBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_build"
  serverConfigBuilderBuild ::
    Ptr ServerConfigBuilder -> Ptr (ConstPtr ServerConfig) -> IO Result

foreign import capi unsafe "rustls.h &rustls_server_config_free"
  serverConfigFree :: FinalizerPtr ServerConfig

foreign import capi unsafe "rustls.h rustls_server_connection_new"
  serverConnectionNew :: ConstPtr ServerConfig -> Ptr (Ptr Connection) -> IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_alpn_protocols"
  serverConfigBuilderSetALPNProtocols ::
    Ptr ServerConfigBuilder -> ConstPtr SliceBytes -> CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_ignore_client_order"
  serverConfigBuilderSetIgnoreClientOrder :: Ptr ServerConfigBuilder -> CBool -> IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_certified_keys"
  serverConfigBuilderSetCertifiedKeys ::
    Ptr ServerConfigBuilder -> ConstPtr (ConstPtr CertifiedKey) -> CSize -> IO Result

data
  {-# CTYPE "rustls.h" "rustls_web_pki_client_cert_verifier_builder" #-}
  WebPkiClientCertVerifierBuilder

data
  {-# CTYPE "rustls.h" "rustls_client_cert_verifier" #-}
  ClientCertVerifier

foreign import capi unsafe "rustls.h rustls_web_pki_client_cert_verifier_builder_new_with_provider"
  webPkiClientCertVerifierBuilderNewWithProvider ::
    ConstPtr CryptoProvider ->
    ConstPtr RootCertStore ->
    IO (Ptr WebPkiClientCertVerifierBuilder)

foreign import capi unsafe "rustls.h rustls_web_pki_client_cert_verifier_builder_add_crl"
  webPkiClientCertVerifierBuilderAddCrl ::
    Ptr WebPkiClientCertVerifierBuilder -> ConstPtr Word8 -> CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated"
  webPkiClientCertVerifierBuilderAllowUnauthenticated ::
    Ptr WebPkiClientCertVerifierBuilder -> IO Result

foreign import capi unsafe "rustls.h rustls_web_pki_client_cert_verifier_builder_free"
  webPkiClientCertVerifierBuilderFree :: Ptr WebPkiClientCertVerifierBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_web_pki_client_cert_verifier_builder_build"
  webPkiClientCertVerifierBuilderBuild ::
    Ptr WebPkiClientCertVerifierBuilder -> Ptr (Ptr ClientCertVerifier) -> IO Result

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_free"
  clientCertVerifierFree :: Ptr ClientCertVerifier -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_client_verifier"
  serverConfigBuilderSetClientVerifier ::
    Ptr ServerConfigBuilder -> ConstPtr ClientCertVerifier -> IO ()

-- connection

data {-# CTYPE "rustls.h" "rustls_connection" #-} Connection

foreign import capi unsafe "rustls.h rustls_connection_free"
  connectionFree :: Ptr Connection -> IO ()

type LogCallback = Ptr Userdata -> ConstPtr LogParams -> IO ()

foreign import ccall "wrapper"
  mkLogCallback :: LogCallback -> IO (FunPtr LogCallback)

newtype LogLevel = LogLevel CSize
  deriving stock (Show, Eq)
  deriving newtype (Storable)

data LogParams = LogParams
  { rustlsLogParamsLevel :: LogLevel,
    rustlsLogParamsMessage :: Str
  }
  deriving stock (Generic)
  deriving anyclass (GStorable)

foreign import capi unsafe "rustls.h rustls_connection_set_log_callback"
  connectionSetLogCallback :: Ptr Connection -> FunPtr LogCallback -> IO ()

foreign import capi unsafe "rustls.h rustls_connection_is_handshaking"
  connectionIsHandshaking :: ConstPtr Connection -> IO CBool

foreign import capi unsafe "rustls.h rustls_connection_get_alpn_protocol"
  connectionGetALPNProtocol :: ConstPtr Connection -> Ptr (ConstPtr Word8) -> Ptr CSize -> IO ()

foreign import capi unsafe "rustls.h rustls_connection_get_protocol_version"
  connectionGetProtocolVersion :: ConstPtr Connection -> IO TLSVersion

foreign import capi unsafe "rustls.h rustls_connection_get_negotiated_ciphersuite"
  connectionGetNegotiatedCipherSuite :: ConstPtr Connection -> IO Word16

foreign import capi unsafe "hs_rustls.h hs_rustls_connection_get_negotiated_ciphersuite_name"
  connectionGetNegotiatedCipherSuiteName :: ConstPtr Connection -> Ptr Str -> IO ()

foreign import capi unsafe "rustls.h rustls_connection_get_negotiated_key_exchange_group"
  connectionGetNegotiatedKeyExchangeGroup :: ConstPtr Connection -> IO Word16

foreign import capi unsafe "hs_rustls.h hs_rustls_connection_get_negotiated_key_exchange_group_name"
  connectionGetNegotiatedKeyExchangeGroupName :: ConstPtr Connection -> Ptr Str -> IO ()

foreign import capi unsafe "hs_rustls.h hs_rustls_connection_handshake_kind"
  connectionHandshakeKind :: ConstPtr Connection -> IO Word16

foreign import capi unsafe "hs_rustls.h hs_rustls_handshake_kind_str"
  handshakeKindStr :: Word16 -> Ptr Str -> IO ()

foreign import capi unsafe "hs_rustls.h hs_rustls_server_connection_get_server_name"
  serverConnectionGetSNIHostname :: ConstPtr Connection -> Ptr Str -> IO ()

foreign import capi unsafe "rustls.h rustls_connection_get_peer_certificate"
  connectionGetPeerCertificate :: ConstPtr Connection -> CSize -> IO (ConstPtr Certificate)

-- connection read

type ReadCallback = Ptr Userdata -> Ptr Word8 -> CSize -> Ptr CSize -> IO IOResult

foreign import ccall "wrapper"
  mkReadCallback :: ReadCallback -> IO (FunPtr ReadCallback)

foreign import capi "rustls.h rustls_connection_read_tls"
  connectionReadTls ::
    Ptr Connection -> FunPtr ReadCallback -> Ptr Userdata -> Ptr CSize -> IO IOResult

foreign import capi "rustls.h rustls_connection_read"
  connectionRead :: Ptr Connection -> Ptr Word8 -> CSize -> Ptr CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_connection_wants_read"
  connectionWantsRead :: ConstPtr Connection -> IO CBool

-- connection write

type WriteCallback = Ptr Userdata -> ConstPtr Word8 -> CSize -> Ptr CSize -> IO IOResult

foreign import ccall "wrapper"
  mkWriteCallback :: WriteCallback -> IO (FunPtr WriteCallback)

foreign import capi "rustls.h rustls_connection_write_tls"
  connectionWriteTls ::
    Ptr Connection -> FunPtr WriteCallback -> Ptr Userdata -> Ptr CSize -> IO IOResult

foreign import capi "rustls.h rustls_connection_write"
  connectionWrite :: Ptr Connection -> Ptr Word8 -> CSize -> Ptr CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_connection_wants_write"
  connectionWantsWrite :: ConstPtr Connection -> IO CBool

-- misc

foreign import capi "rustls.h rustls_connection_process_new_packets"
  connectionProcessNewPackets :: Ptr Connection -> IO Result

foreign import capi "rustls.h rustls_connection_send_close_notify"
  connectionSendCloseNotify :: Ptr Connection -> IO ()

-- TODO high level bindings?
foreign import capi unsafe "rustls.h rustls_connection_set_buffer_limit"
  connectionSetBufferLimit :: Ptr Connection -> CSize -> IO ()

data {-# CTYPE "rustls.h" "rustls_certified_key" #-} CertifiedKey

foreign import capi unsafe "rustls.h rustls_certified_key_build"
  certifiedKeyBuild ::
    ConstPtr Word8 -> CSize -> ConstPtr Word8 -> CSize -> Ptr (ConstPtr CertifiedKey) -> IO Result

foreign import capi unsafe "rustls.h rustls_certified_key_free"
  certifiedKeyFree :: ConstPtr CertifiedKey -> IO ()

data {-# CTYPE "rustls.h" "rustls_certificate" #-} Certificate

foreign import capi unsafe "rustls.h rustls_certificate_get_der"
  certificateGetDER :: ConstPtr Certificate -> Ptr (ConstPtr Word8) -> Ptr CSize -> IO Result

-- TLS params

data {-# CTYPE "rustls.h" "rustls_supported_ciphersuite" #-} SupportedCipherSuite

foreign import capi unsafe "rustls.h rustls_supported_ciphersuite_get_suite"
  supportedCipherSuiteGetSuite :: ConstPtr SupportedCipherSuite -> Word16

foreign import capi unsafe "hs_rustls.h hs_rustls_supported_ciphersuite_get_name"
  hsSupportedCipherSuiteGetName :: ConstPtr SupportedCipherSuite -> Ptr Str -> IO ()

foreign import capi unsafe "hs_rustls.h hs_rustls_supported_ciphersuite_protocol_version"
  hsSupportedCiphersuiteProtocolVersion :: ConstPtr SupportedCipherSuite -> IO TLSVersion

-- | A TLS protocol version supported by Rustls.
newtype {-# CTYPE "stdint.h" "uint16_t" #-} TLSVersion = TLSVersion
  { unTLSVersion :: Word16
  }
  deriving stock (Show, Eq, Ord)
  deriving newtype (Storable)

pattern TLS12, TLS13 :: TLSVersion
pattern TLS12 = TLSVersion 0x0303
pattern TLS13 = TLSVersion 0x0304

-- Crypto provider

data {-# CTYPE "rustls.h" "rustls_crypto_provider" #-} CryptoProvider

data {-# CTYPE "rustls.h" "rustls_crypto_provider_builder" #-} CryptoProviderBuilder

foreign import capi unsafe "rustls.h rustls_crypto_provider_builder_new_from_default"
  cryptoProviderBuilderNewFromDefault :: Ptr (Ptr CryptoProviderBuilder) -> IO Result

foreign import capi unsafe "rustls.h rustls_crypto_provider_builder_new_with_base"
  cryptoProviderBuilderNewWithBase :: ConstPtr CryptoProvider -> IO (Ptr CryptoProviderBuilder)

foreign import capi unsafe "rustls.h rustls_crypto_provider_builder_set_cipher_suites"
  cryptoProviderBuilderSetCipherSuites ::
    Ptr CryptoProviderBuilder ->
    ConstPtr (ConstPtr SupportedCipherSuite) ->
    CSize ->
    IO Result

foreign import capi unsafe "rustls.h rustls_crypto_provider_builder_build"
  cryptoProviderBuilderBuild ::
    Ptr CryptoProviderBuilder ->
    Ptr (ConstPtr CryptoProvider) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_crypto_provider_builder_free"
  cryptoProviderBuilderFree :: Ptr CryptoProviderBuilder -> IO ()

foreign import capi unsafe "rustls.h &rustls_crypto_provider_free"
  cryptoProviderFree :: FinalizerPtr CryptoProvider

foreign import capi unsafe "rustls.h rustls_crypto_provider_ciphersuites_len"
  cryptoProviderCiphersuitesLen :: ConstPtr CryptoProvider -> CSize

foreign import capi unsafe "rustls.h rustls_crypto_provider_ciphersuites_get"
  cryptoProviderCiphersuitesGet ::
    ConstPtr CryptoProvider -> CSize -> ConstPtr SupportedCipherSuite

-- Root cert store

data {-# CTYPE "rustls.h" "rustls_root_cert_store_builder" #-} RootCertStoreBuilder

data {-# CTYPE "rustls.h" "rustls_root_cert_store" #-} RootCertStore

foreign import capi unsafe "rustls.h rustls_root_cert_store_builder_new"
  rootCertStoreBuilderNew :: IO (Ptr RootCertStoreBuilder)

foreign import capi unsafe "rustls.h rustls_root_cert_store_builder_add_pem"
  rootCertStoreBuilderAddPem ::
    Ptr RootCertStoreBuilder -> ConstPtr Word8 -> CSize -> CBool -> IO Result

foreign import capi unsafe "rustls.h rustls_root_cert_store_builder_load_roots_from_file"
  rootCertStoreBuilderLoadRootsFromFile ::
    Ptr RootCertStoreBuilder -> ConstCString -> CBool -> IO Result

foreign import capi unsafe "rustls.h rustls_root_cert_store_builder_free"
  rootCertStoreBuilderFree :: Ptr RootCertStoreBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_root_cert_store_builder_build"
  rootCertStoreBuilderBuild ::
    Ptr RootCertStoreBuilder -> Ptr (ConstPtr RootCertStore) -> IO Result

foreign import capi unsafe "rustls.h rustls_root_cert_store_free"
  rootCertStoreFree :: ConstPtr RootCertStore -> IO ()
