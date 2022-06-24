#if DERIVE_STORABLE_PLUGIN
{-# OPTIONS_GHC -fplugin=Foreign.Storable.Generic.Plugin #-}
#endif

-- | Internal module, not subject to PVP.
module Rustls.Internal.FFI
  ( -- * Client

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
    clientConfigBuilderLoadRootsFromFile,
    clientConfigBuilderUseRoots,

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
    ClientCertVerifier,
    clientCertVerifierNew,
    clientCertVerifierFree,
    serverConfigBuilderSetClientVerifier,
    ClientCertVerifierOptional,
    clientCertVerifierOptionalNew,
    clientCertVerifierOptionalFree,
    serverConfigBuilderSetClientVerifierOptional,

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
    ReadWriteCallback,
    mkReadWriteCallback,

    -- *** Read
    connectionWantsRead,
    connectionRead,
    connectionReadTls,

    -- *** Write
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
    allCipherSuites,
    allCipherSuitesLen,
    defaultCipherSuites,
    defaultCipherSuitesLen,
    supportedCipherSuiteGetSuite,
    hsSupportedCipherSuiteGetName,
    TLSVersion (..),
    pattern TLS12,
    pattern TLS13,
    allVersions,
    allVersionsLen,
    defaultVersions,
    defaultVersionsLen,

    -- ** Root cert store
    RootCertStore,
    rootCertStoreNew,
    rootCertStoreAddPEM,
    rootCertStoreFree,
  )
where

import Data.Word
import Foreign
import Foreign.C
import Foreign.Storable.Generic
import GHC.Generics (Generic)

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
    Ptr (Ptr SupportedCipherSuite) ->
    CSize ->
    Ptr TLSVersion ->
    CSize ->
    Ptr (Ptr ClientConfigBuilder) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_free"
  clientConfigBuilderFree :: Ptr ClientConfigBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_build"
  clientConfigBuilderBuild :: Ptr ClientConfigBuilder -> IO (Ptr ClientConfig)

foreign import capi unsafe "rustls.h &rustls_client_config_free"
  clientConfigFree :: FinalizerPtr ClientConfig

foreign import capi unsafe "rustls.h rustls_client_connection_new"
  clientConnectionNew ::
    Ptr ClientConfig ->
    -- | Hostname.
    CString ->
    Ptr (Ptr Connection) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_load_roots_from_file"
  clientConfigBuilderLoadRootsFromFile :: Ptr ClientConfigBuilder -> CString -> IO Result

data {-# CTYPE "rustls.h" "rustls_root_cert_store" #-} RootCertStore

foreign import capi unsafe "rustls.h rustls_root_cert_store_new"
  rootCertStoreNew :: IO (Ptr RootCertStore)

foreign import capi unsafe "rustls.h rustls_root_cert_store_add_pem"
  rootCertStoreAddPEM :: Ptr RootCertStore -> Ptr Word8 -> CSize -> CBool -> IO Result

foreign import capi unsafe "rustls.h rustls_root_cert_store_free"
  rootCertStoreFree :: Ptr RootCertStore -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_use_roots"
  clientConfigBuilderUseRoots :: Ptr ClientConfigBuilder -> Ptr RootCertStore -> IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_alpn_protocols"
  clientConfigBuilderSetALPNProtocols :: Ptr ClientConfigBuilder -> Ptr SliceBytes -> CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_enable_sni"
  clientConfigBuilderSetEnableSNI :: Ptr ClientConfigBuilder -> CBool -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_certified_key"
  clientConfigBuilderSetCertifiedKey :: Ptr ClientConfigBuilder -> Ptr (Ptr CertifiedKey) -> CSize -> IO Result

-- TODO add callback-based cert validation?

-- Server
data {-# CTYPE "rustls.h" "rustls_server_config" #-} ServerConfig

data {-# CTYPE "rustls.h" "rustls_server_config_builder" #-} ServerConfigBuilder

foreign import capi unsafe "rustls.h rustls_server_config_builder_new_custom"
  serverConfigBuilderNewCustom ::
    Ptr (Ptr SupportedCipherSuite) ->
    CSize ->
    Ptr TLSVersion ->
    CSize ->
    Ptr (Ptr ServerConfigBuilder) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_free"
  serverConfigBuilderFree :: Ptr ServerConfigBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_build"
  serverConfigBuilderBuild :: Ptr ServerConfigBuilder -> IO (Ptr ServerConfig)

foreign import capi unsafe "rustls.h &rustls_server_config_free"
  serverConfigFree :: FinalizerPtr ServerConfig

foreign import capi unsafe "rustls.h rustls_server_connection_new"
  serverConnectionNew :: Ptr ServerConfig -> Ptr (Ptr Connection) -> IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_alpn_protocols"
  serverConfigBuilderSetALPNProtocols :: Ptr ServerConfigBuilder -> Ptr SliceBytes -> CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_ignore_client_order"
  serverConfigBuilderSetIgnoreClientOrder :: Ptr ServerConfigBuilder -> CBool -> IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_certified_keys"
  serverConfigBuilderSetCertifiedKeys :: Ptr ServerConfigBuilder -> Ptr (Ptr CertifiedKey) -> CSize -> IO Result

data {-# CTYPE "rustls.h" "rustls_client_cert_verifier" #-} ClientCertVerifier

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_new"
  clientCertVerifierNew :: Ptr RootCertStore -> IO (Ptr ClientCertVerifier)

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_free"
  clientCertVerifierFree :: Ptr ClientCertVerifier -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_client_verifier"
  serverConfigBuilderSetClientVerifier :: Ptr ServerConfigBuilder -> Ptr ClientCertVerifier -> IO ()

data {-# CTYPE "rustls.h" "rustls_client_cert_verifier_optional" #-} ClientCertVerifierOptional

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_optional_new"
  clientCertVerifierOptionalNew :: Ptr RootCertStore -> IO (Ptr ClientCertVerifierOptional)

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_optional_free"
  clientCertVerifierOptionalFree :: Ptr ClientCertVerifierOptional -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_client_verifier_optional"
  serverConfigBuilderSetClientVerifierOptional :: Ptr ServerConfigBuilder -> Ptr ClientCertVerifierOptional -> IO ()

-- add custom session persistence functions?

-- connection

data {-# CTYPE "rustls.h" "rustls_connection" #-} Connection

foreign import capi unsafe "rustls.h rustls_connection_free"
  connectionFree :: Ptr Connection -> IO ()

type LogCallback = Ptr Userdata -> Ptr LogParams -> IO ()

foreign import ccall "wrapper"
  mkLogCallback :: LogCallback -> IO (FunPtr LogCallback)

newtype LogLevel = LogLevel CSize
  deriving stock (Eq)
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
  connectionIsHandshaking :: Ptr Connection -> IO CBool

foreign import capi unsafe "rustls.h rustls_connection_get_alpn_protocol"
  connectionGetALPNProtocol :: Ptr Connection -> Ptr (Ptr Word8) -> Ptr CSize -> IO ()

foreign import capi unsafe "rustls.h rustls_connection_get_protocol_version"
  connectionGetProtocolVersion :: Ptr Connection -> IO TLSVersion

foreign import capi unsafe "rustls.h rustls_connection_get_negotiated_ciphersuite"
  connectionGetNegotiatedCipherSuite :: Ptr Connection -> IO (Ptr SupportedCipherSuite)

foreign import capi unsafe "rustls.h rustls_server_connection_get_sni_hostname"
  serverConnectionGetSNIHostname :: Ptr Connection -> Ptr Word8 -> CSize -> Ptr CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_connection_get_peer_certificate"
  connectionGetPeerCertificate :: Ptr Connection -> CSize -> IO (Ptr Certificate)

-- connection read/write

type ReadWriteCallback = Ptr Userdata -> Ptr Word8 -> CSize -> Ptr CSize -> IO IOResult

foreign import ccall "wrapper"
  mkReadWriteCallback :: ReadWriteCallback -> IO (FunPtr ReadWriteCallback)

-- connection read

foreign import capi "rustls.h rustls_connection_read_tls"
  connectionReadTls ::
    Ptr Connection -> FunPtr ReadWriteCallback -> Ptr Userdata -> Ptr CSize -> IO IOResult

foreign import capi "rustls.h rustls_connection_read"
  connectionRead :: Ptr Connection -> Ptr Word8 -> CSize -> Ptr CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_connection_wants_read"
  connectionWantsRead :: Ptr Connection -> IO CBool

-- connection write

foreign import capi "rustls.h rustls_connection_write_tls"
  connectionWriteTls ::
    Ptr Connection -> FunPtr ReadWriteCallback -> Ptr Userdata -> Ptr CSize -> IO IOResult

foreign import capi "rustls.h rustls_connection_write"
  connectionWrite :: Ptr Connection -> Ptr Word8 -> CSize -> Ptr CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_connection_wants_write"
  connectionWantsWrite :: Ptr Connection -> IO CBool

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
  certifiedKeyBuild :: Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr (Ptr CertifiedKey) -> IO Result

foreign import capi unsafe "rustls.h rustls_certified_key_free"
  certifiedKeyFree :: Ptr CertifiedKey -> IO ()

data {-# CTYPE "rustls.h" "rustls_certificate" #-} Certificate

foreign import capi unsafe "rustls.h rustls_certificate_get_der"
  certificateGetDER :: Ptr Certificate -> Ptr (Ptr Word8) -> Ptr CSize -> IO Result

-- TLS params

data {-# CTYPE "rustls.h" "rustls_supported_ciphersuite" #-} SupportedCipherSuite

foreign import capi "rustls.h value RUSTLS_ALL_CIPHER_SUITES"
  allCipherSuites :: Ptr (Ptr SupportedCipherSuite)

foreign import capi "rustls.h value RUSTLS_ALL_CIPHER_SUITES_LEN"
  allCipherSuitesLen :: CSize

foreign import capi "rustls.h value RUSTLS_DEFAULT_CIPHER_SUITES"
  defaultCipherSuites :: Ptr (Ptr SupportedCipherSuite)

foreign import capi "rustls.h value RUSTLS_DEFAULT_CIPHER_SUITES_LEN"
  defaultCipherSuitesLen :: CSize

foreign import capi unsafe "rustls.h rustls_supported_ciphersuite_get_suite"
  supportedCipherSuiteGetSuite :: Ptr SupportedCipherSuite -> Word16

foreign import capi unsafe "hs_rustls.h hs_rustls_supported_ciphersuite_get_name"
  hsSupportedCipherSuiteGetName :: Ptr SupportedCipherSuite -> Ptr Str -> IO ()

-- | A TLS protocol version supported by Rustls.
newtype {-# CTYPE "stdint.h" "uint16_t" #-} TLSVersion = TLSVersion
  { unTLSVersion :: Word16
  }
  deriving stock (Show, Eq, Ord)
  deriving newtype (Storable)

pattern TLS12, TLS13 :: TLSVersion
pattern TLS12 = TLSVersion 0x0303
pattern TLS13 = TLSVersion 0x0304

foreign import capi "rustls.h value RUSTLS_ALL_VERSIONS"
  allVersions :: Ptr TLSVersion

foreign import capi "rustls.h value RUSTLS_ALL_VERSIONS_LEN"
  allVersionsLen :: CSize

foreign import capi "rustls.h value RUSTLS_DEFAULT_VERSIONS"
  defaultVersions :: Ptr TLSVersion

foreign import capi "rustls.h value RUSTLS_DEFAULT_VERSIONS_LEN"
  defaultVersionsLen :: CSize
