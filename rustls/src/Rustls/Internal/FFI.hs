#if DERIVE_STORABLE_PLUGIN
{-# OPTIONS_GHC -fplugin=Foreign.Storable.Generic.Plugin #-}
#endif

-- | Internal module, not subject to PVP.
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
    ConstPtr (ConstPtr SupportedCipherSuite) ->
    CSize ->
    ConstPtr TLSVersion ->
    CSize ->
    Ptr (Ptr ClientConfigBuilder) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_free"
  clientConfigBuilderFree :: Ptr ClientConfigBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_build"
  clientConfigBuilderBuild :: Ptr ClientConfigBuilder -> IO (ConstPtr ClientConfig)

foreign import capi unsafe "rustls.h &rustls_client_config_free"
  clientConfigFree :: FinalizerPtr ClientConfig

foreign import capi unsafe "rustls.h rustls_client_connection_new"
  clientConnectionNew ::
    ConstPtr ClientConfig ->
    -- | Hostname.
    ConstCString ->
    Ptr (Ptr Connection) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_load_roots_from_file"
  clientConfigBuilderLoadRootsFromFile :: Ptr ClientConfigBuilder -> ConstCString -> IO Result

data {-# CTYPE "rustls.h" "rustls_root_cert_store" #-} RootCertStore

foreign import capi unsafe "rustls.h rustls_root_cert_store_new"
  rootCertStoreNew :: IO (Ptr RootCertStore)

foreign import capi unsafe "rustls.h rustls_root_cert_store_add_pem"
  rootCertStoreAddPEM :: Ptr RootCertStore -> ConstPtr Word8 -> CSize -> CBool -> IO Result

foreign import capi unsafe "rustls.h rustls_root_cert_store_free"
  rootCertStoreFree :: Ptr RootCertStore -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_use_roots"
  clientConfigBuilderUseRoots :: Ptr ClientConfigBuilder -> ConstPtr RootCertStore -> IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_alpn_protocols"
  clientConfigBuilderSetALPNProtocols ::
    Ptr ClientConfigBuilder -> ConstPtr SliceBytes -> CSize -> IO Result

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_enable_sni"
  clientConfigBuilderSetEnableSNI :: Ptr ClientConfigBuilder -> CBool -> IO ()

foreign import capi unsafe "rustls.h rustls_client_config_builder_set_certified_key"
  clientConfigBuilderSetCertifiedKey ::
    Ptr ClientConfigBuilder -> ConstPtr (ConstPtr CertifiedKey) -> CSize -> IO Result

-- TODO add callback-based cert validation?

-- Server
data {-# CTYPE "rustls.h" "rustls_server_config" #-} ServerConfig

data {-# CTYPE "rustls.h" "rustls_server_config_builder" #-} ServerConfigBuilder

foreign import capi unsafe "rustls.h rustls_server_config_builder_new_custom"
  serverConfigBuilderNewCustom ::
    ConstPtr (ConstPtr SupportedCipherSuite) ->
    CSize ->
    ConstPtr TLSVersion ->
    CSize ->
    Ptr (Ptr ServerConfigBuilder) ->
    IO Result

foreign import capi unsafe "rustls.h rustls_server_config_builder_free"
  serverConfigBuilderFree :: Ptr ServerConfigBuilder -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_build"
  serverConfigBuilderBuild :: Ptr ServerConfigBuilder -> IO (ConstPtr ServerConfig)

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

data {-# CTYPE "rustls.h" "rustls_client_cert_verifier" #-} ClientCertVerifier

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_new"
  clientCertVerifierNew :: ConstPtr RootCertStore -> IO (ConstPtr ClientCertVerifier)

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_free"
  clientCertVerifierFree :: ConstPtr ClientCertVerifier -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_client_verifier"
  serverConfigBuilderSetClientVerifier ::
    Ptr ServerConfigBuilder -> ConstPtr ClientCertVerifier -> IO ()

data {-# CTYPE "rustls.h" "rustls_client_cert_verifier_optional" #-} ClientCertVerifierOptional

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_optional_new"
  clientCertVerifierOptionalNew ::
    ConstPtr RootCertStore -> IO (ConstPtr ClientCertVerifierOptional)

foreign import capi unsafe "rustls.h rustls_client_cert_verifier_optional_free"
  clientCertVerifierOptionalFree :: ConstPtr ClientCertVerifierOptional -> IO ()

foreign import capi unsafe "rustls.h rustls_server_config_builder_set_client_verifier_optional"
  serverConfigBuilderSetClientVerifierOptional ::
    Ptr ServerConfigBuilder -> ConstPtr ClientCertVerifierOptional -> IO ()

-- add custom session persistence functions?

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
  connectionGetNegotiatedCipherSuite :: ConstPtr Connection -> IO (ConstPtr SupportedCipherSuite)

foreign import capi unsafe "rustls.h rustls_server_connection_get_sni_hostname"
  serverConnectionGetSNIHostname :: ConstPtr Connection -> Ptr Word8 -> CSize -> Ptr CSize -> IO Result

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

foreign import capi "rustls.h value RUSTLS_ALL_CIPHER_SUITES"
  allCipherSuites :: ConstPtr (Ptr SupportedCipherSuite)

foreign import capi "rustls.h value RUSTLS_ALL_CIPHER_SUITES_LEN"
  allCipherSuitesLen :: CSize

foreign import capi "rustls.h value RUSTLS_DEFAULT_CIPHER_SUITES"
  defaultCipherSuites :: ConstPtr (ConstPtr SupportedCipherSuite)

foreign import capi "rustls.h value RUSTLS_DEFAULT_CIPHER_SUITES_LEN"
  defaultCipherSuitesLen :: CSize

foreign import capi unsafe "rustls.h rustls_supported_ciphersuite_get_suite"
  supportedCipherSuiteGetSuite :: ConstPtr SupportedCipherSuite -> Word16

foreign import capi unsafe "hs_rustls.h hs_rustls_supported_ciphersuite_get_name"
  hsSupportedCipherSuiteGetName :: ConstPtr SupportedCipherSuite -> Ptr Str -> IO ()

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
  allVersions :: ConstPtr TLSVersion

foreign import capi "rustls.h value RUSTLS_ALL_VERSIONS_LEN"
  allVersionsLen :: CSize

foreign import capi "rustls.h value RUSTLS_DEFAULT_VERSIONS"
  defaultVersions :: ConstPtr TLSVersion

foreign import capi "rustls.h value RUSTLS_DEFAULT_VERSIONS_LEN"
  defaultVersionsLen :: CSize
