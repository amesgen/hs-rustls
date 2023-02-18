-- | TLS bindings for [Rustls](https://github.com/rustls/rustls) via
-- [rustls-ffi](https://github.com/rustls/rustls-ffi).
--
-- See the [README on GitHub](https://github.com/amesgen/hs-rustls/tree/main/rustls)
-- for setup instructions.
--
-- Currently, most of the functionality exposed by rustls-ffi is available,
-- while rustls-ffi is still missing some more niche Rustls features.
--
-- Also see [http-client-rustls](https://hackage.haskell.org/package/http-client-rustls)
-- for making HTTPS requests using
-- [http-client](https://hackage.haskell.org/package/http-client) and Rustls.
--
-- == Client example
--
-- Suppose you have alread opened a 'Network.Socket.Socket' to @example.org@,
-- port 443 (see e.g. the examples at "Network.Socket"). This small example
-- showcases how to perform a simple HTTP GET request:
--
-- >>> :set -XOverloadedStrings
-- >>> import qualified Rustls
-- >>> import Network.Socket (Socket)
-- >>> import Data.Acquire (withAcquire)
-- >>> :{
-- example :: Socket -> IO ()
-- example socket = do
--   -- It is encouraged to share a single `clientConfig` when creating multiple
--   -- TLS connections.
--   clientConfig <-
--     Rustls.buildClientConfig $ Rustls.defaultClientConfigBuilder roots
--   let newConnection =
--         Rustls.newClientConnection socket clientConfig "example.org"
--   withAcquire newConnection $ \conn -> do
--     Rustls.writeBS conn "GET /"
--     recv <- Rustls.readBS conn 1000 -- max number of bytes to read
--     print recv
--   where
--     -- For now, rustls-ffi does not provide a built-in way to access
--     -- the OS certificate store.
--     roots = Rustls.ClientRootsFromFile "/etc/ssl/certs/ca-certificates.crt"
-- :}
--
-- == Using 'Acquire'
--
-- Some API functions (like 'newClientConnection' and 'newServerConnection')
-- return an 'Acquire' from
-- [resourcet](https://hackage.haskell.org/package/resourcet), as it is a
-- convenient abstraction for exposing a value that should be consumed in a
-- "bracketed" manner.
--
-- Usually, it can be used via 'Data.Acquire.with' or 'withAcquire', or via
-- 'allocateAcquire' when a 'Control.Monad.Trans.Resource.MonadResource'
-- constraint is available. If you really need the extra flexibility, you can
-- also access separate @open…@ and @close…@ functions by reaching for
-- "Data.Acquire.Internal".
module Rustls
  ( -- * Client

    -- ** Builder
    ClientConfigBuilder (..),
    defaultClientConfigBuilder,
    ClientRoots (..),
    PEMCertificates (..),

    -- ** Config
    ClientConfig,
    clientConfigLogCallback,
    buildClientConfig,

    -- ** Open a connection
    newClientConnection,

    -- * Server

    -- ** Builder
    ServerConfigBuilder (..),
    defaultServerConfigBuilder,
    ClientCertVerifier (..),

    -- ** Config
    ServerConfig,
    serverConfigLogCallback,
    buildServerConfig,

    -- ** Open a connection
    newServerConnection,

    -- * Connection
    Connection,
    Side (..),

    -- ** Read and write
    readBS,
    writeBS,

    -- ** Handshaking
    handshake,
    HandshakeQuery,
    getALPNProtocol,
    getTLSVersion,
    getCipherSuite,
    getSNIHostname,
    getPeerCertificate,

    -- ** Closing
    sendCloseNotify,

    -- ** Logging
    LogCallback,
    newLogCallback,
    LogLevel (..),

    -- ** Raw 'Ptr'-based API
    readPtr,
    writePtr,

    -- * Misc
    version,

    -- ** Backend
    Backend (..),
    ByteStringBackend (..),

    -- ** Types
    ALPNProtocol (..),
    CertifiedKey (..),
    DERCertificate (..),
    TLSVersion (TLS12, TLS13, unTLSVersion),
    defaultTLSVersions,
    allTLSVersions,
    CipherSuite,
    cipherSuiteID,
    showCipherSuite,
    defaultCipherSuites,
    allCipherSuites,

    -- ** Exceptions
    RustlsException,
    isCertError,
    RustlsLogException (..),
  )
where

import Control.Concurrent (forkFinally, killThread)
import Control.Concurrent.MVar
import qualified Control.Exception as E
import Control.Monad (forever, when, (<=<))
import Control.Monad.IO.Class
import Control.Monad.Trans.Cont
import Control.Monad.Trans.Reader
import Data.Acquire
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Unsafe as BU
import Data.Coerce
import Data.Foldable (for_)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Foreign as T
import Foreign
import Foreign.C
import GHC.Conc (reportError)
import GHC.Generics (Generic)
import Rustls.Internal
import Rustls.Internal.FFI (TLSVersion (..))
import qualified Rustls.Internal.FFI as FFI
import System.IO.Unsafe (unsafePerformIO)

-- $setup
-- >>> import Control.Monad.IO.Class
-- >>> import Data.Acquire

-- | Combined version string of Rustls and rustls-ffi.
--
-- >>> version
-- "rustls-ffi/0.9.2/rustls/0.20.8"
version :: Text
version = unsafePerformIO $ alloca \strPtr -> do
  FFI.hsVersion strPtr
  strToText =<< peek strPtr
{-# NOINLINE version #-}

peekNonEmpty :: (Storable a, Coercible a b) => Ptr a -> CSize -> NonEmpty b
peekNonEmpty as len =
  NE.fromList . coerce . unsafePerformIO $ peekArray (cSizeToInt len) as

-- | All 'TLSVersion's supported by Rustls.
allTLSVersions :: NonEmpty TLSVersion
allTLSVersions = peekNonEmpty FFI.allVersions FFI.allVersionsLen
{-# NOINLINE allTLSVersions #-}

-- | The default 'TLSVersion's used by Rustls. A subset of 'allTLSVersions'.
defaultTLSVersions :: NonEmpty TLSVersion
defaultTLSVersions = peekNonEmpty FFI.defaultVersions FFI.defaultVersionsLen
{-# NOINLINE defaultTLSVersions #-}

-- | All 'CipherSuite's supported by Rustls.
allCipherSuites :: NonEmpty CipherSuite
allCipherSuites = peekNonEmpty FFI.allCipherSuites FFI.allCipherSuitesLen
{-# NOINLINE allCipherSuites #-}

-- | The default 'CipherSuite's used by Rustls. A subset of 'allCipherSuites'.
defaultCipherSuites :: NonEmpty CipherSuite
defaultCipherSuites = peekNonEmpty FFI.defaultCipherSuites FFI.defaultCipherSuitesLen
{-# NOINLINE defaultCipherSuites #-}

-- | A 'ClientConfigBuilder' with good defaults.
defaultClientConfigBuilder :: ClientRoots -> ClientConfigBuilder
defaultClientConfigBuilder roots =
  ClientConfigBuilder
    { clientConfigTLSVersions = [],
      clientConfigCipherSuites = [],
      clientConfigRoots = roots,
      clientConfigALPNProtocols = [],
      clientConfigEnableSNI = True,
      clientConfigCertifiedKeys = []
    }

withCertifiedKeys :: [CertifiedKey] -> ((Ptr (Ptr FFI.CertifiedKey), CSize) -> IO a) -> IO a
withCertifiedKeys certifiedKeys cb =
  withMany withCertifiedKey certifiedKeys \certKeys ->
    withArrayLen certKeys \len ptr -> cb (ptr, intToCSize len)
  where
    withCertifiedKey CertifiedKey {..} cb =
      BU.unsafeUseAsCStringLen certificateChain \(castPtr -> certPtr, intToCSize -> certLen) ->
        BU.unsafeUseAsCStringLen privateKey \(castPtr -> privPtr, intToCSize -> privLen) ->
          alloca \certKeyPtr -> do
            rethrowR =<< FFI.certifiedKeyBuild certPtr certLen privPtr privLen certKeyPtr
            cb =<< peek certKeyPtr

withALPNProtocols :: [ALPNProtocol] -> ((Ptr FFI.SliceBytes, CSize) -> IO a) -> IO a
withALPNProtocols bss cb = do
  withMany withSliceBytes (coerce bss) \bsPtrs ->
    withArrayLen bsPtrs \len bsPtr -> cb (bsPtr, intToCSize len)
  where
    withSliceBytes bs cb =
      BU.unsafeUseAsCStringLen bs \(castPtr -> buf, intToCSize -> len) ->
        cb $ FFI.SliceBytes buf len

configBuilderNew ::
  ( Ptr (Ptr FFI.SupportedCipherSuite) ->
    CSize ->
    Ptr TLSVersion ->
    CSize ->
    Ptr (Ptr configBuilder) ->
    IO FFI.Result
  ) ->
  [CipherSuite] ->
  [TLSVersion] ->
  IO (Ptr configBuilder)
configBuilderNew configBuilderNewCustom cipherSuites tlsVersions = evalContT do
  builderPtr <- ContT alloca
  (cipherSuitesLen, cipherSuitesPtr) <-
    if null cipherSuites
      then pure (FFI.defaultCipherSuitesLen, FFI.defaultCipherSuites)
      else ContT \cb -> withArrayLen (coerce cipherSuites) \len ptr ->
        cb (intToCSize len, ptr)
  (tlsVersionsLen, tlsVersionsPtr) <-
    if null tlsVersions
      then pure (FFI.defaultVersionsLen, FFI.defaultVersions)
      else ContT \cb -> withArrayLen tlsVersions \len ptr ->
        cb (intToCSize len, ptr)
  liftIO do
    rethrowR
      =<< configBuilderNewCustom
        cipherSuitesPtr
        cipherSuitesLen
        tlsVersionsPtr
        tlsVersionsLen
        builderPtr
    peek builderPtr

withRootCertStore :: [PEMCertificates] -> (Ptr FFI.RootCertStore -> IO a) -> IO a
withRootCertStore certs action =
  E.bracket FFI.rootCertStoreNew FFI.rootCertStoreFree \store -> do
    let addPEM bs (fromBool @CBool -> strict) = BU.unsafeUseAsCStringLen bs \(buf, len) ->
          rethrowR =<< FFI.rootCertStoreAddPEM store (castPtr buf) (intToCSize len) strict
    for_ certs \case
      PEMCertificatesStrict bs -> addPEM bs True
      PEMCertificatesLax bs -> addPEM bs False
    action store

-- | Build a 'ClientConfigBuilder' into a 'ClientConfig'.
--
-- This is a relatively expensive operation, so it is a good idea to share one
-- 'ClientConfig' when creating multiple 'Connection's.
buildClientConfig :: (MonadIO m) => ClientConfigBuilder -> m ClientConfig
buildClientConfig ClientConfigBuilder {..} = liftIO . E.mask_ $
  E.bracketOnError
    ( configBuilderNew
        FFI.clientConfigBuilderNewCustom
        clientConfigCipherSuites
        clientConfigTLSVersions
    )
    FFI.clientConfigBuilderFree
    \builder -> do
      case clientConfigRoots of
        ClientRootsFromFile rootsPath ->
          withCString rootsPath $
            rethrowR <=< FFI.clientConfigBuilderLoadRootsFromFile builder
        ClientRootsInMemory certs ->
          withRootCertStore certs $ rethrowR <=< FFI.clientConfigBuilderUseRoots builder
      withALPNProtocols clientConfigALPNProtocols \(alpnPtr, len) ->
        rethrowR =<< FFI.clientConfigBuilderSetALPNProtocols builder alpnPtr len
      FFI.clientConfigBuilderSetEnableSNI builder (fromBool @CBool clientConfigEnableSNI)
      withCertifiedKeys clientConfigCertifiedKeys \(ptr, len) ->
        rethrowR =<< FFI.clientConfigBuilderSetCertifiedKey builder ptr len
      let clientConfigLogCallback = Nothing
      clientConfigPtr <-
        newForeignPtr FFI.clientConfigFree =<< FFI.clientConfigBuilderBuild builder
      pure ClientConfig {..}

-- | Build a 'ServerConfigBuilder' into a 'ServerConfig'.
--
-- This is a relatively expensive operation, so it is a good idea to share one
-- 'ServerConfig' when creating multiple 'Connection's.
buildServerConfig :: (MonadIO m) => ServerConfigBuilder -> m ServerConfig
buildServerConfig ServerConfigBuilder {..} = liftIO . E.mask_ $
  E.bracketOnError
    ( configBuilderNew
        FFI.serverConfigBuilderNewCustom
        serverConfigCipherSuites
        serverConfigTLSVersions
    )
    FFI.serverConfigBuilderFree
    \builder -> do
      withALPNProtocols serverConfigALPNProtocols \(alpnPtr, len) ->
        rethrowR =<< FFI.serverConfigBuilderSetALPNProtocols builder alpnPtr len
      rethrowR
        =<< FFI.serverConfigBuilderSetIgnoreClientOrder
          builder
          (fromBool @CBool serverConfigIgnoreClientOrder)
      withCertifiedKeys (NE.toList serverConfigCertifiedKeys) \(ptr, len) ->
        rethrowR =<< FFI.serverConfigBuilderSetCertifiedKeys builder ptr len
      let setBuilderCCV certs ccvNew ccvFree setCCV =
            withRootCertStore certs \roots ->
              E.bracket (ccvNew roots) ccvFree $ setCCV builder
      for_ serverConfigClientCertVerifier \case
        ClientCertVerifier certs -> do
          setBuilderCCV
            certs
            FFI.clientCertVerifierNew
            FFI.clientCertVerifierFree
            FFI.serverConfigBuilderSetClientVerifier
        ClientCertVerifierOptional certs -> do
          setBuilderCCV
            certs
            FFI.clientCertVerifierOptionalNew
            FFI.clientCertVerifierOptionalFree
            FFI.serverConfigBuilderSetClientVerifierOptional
      serverConfigPtr <-
        newForeignPtr FFI.serverConfigFree =<< FFI.serverConfigBuilderBuild builder
      let serverConfigLogCallback = Nothing
      pure ServerConfig {..}

-- | A 'ServerConfigBuilder' with good defaults.
defaultServerConfigBuilder :: NonEmpty CertifiedKey -> ServerConfigBuilder
defaultServerConfigBuilder certifiedKeys =
  ServerConfigBuilder
    { serverConfigCertifiedKeys = certifiedKeys,
      serverConfigTLSVersions = [],
      serverConfigCipherSuites = [],
      serverConfigALPNProtocols = [],
      serverConfigIgnoreClientOrder = False,
      serverConfigClientCertVerifier = Nothing
    }

-- | Allocate a new logging callback, taking a 'LogLevel' and a message.
--
-- If it throws an exception, it will be wrapped in a 'RustlsLogException' and
-- passed to 'reportError'.
--
-- 🚫 Make sure that its lifetime encloses those of the 'Connection's which you
-- configured to use it.
newLogCallback :: (LogLevel -> Text -> IO ()) -> Acquire LogCallback
newLogCallback cb = fmap LogCallback . flip mkAcquire freeHaskellFunPtr $
  FFI.mkLogCallback \_ logParamsPtr -> ignoreExceptions do
    FFI.LogParams {..} <- peek logParamsPtr
    let logLevel = case rustlsLogParamsLevel of
          FFI.LogLevel 1 -> Right LogLevelError
          FFI.LogLevel 2 -> Right LogLevelWarn
          FFI.LogLevel 3 -> Right LogLevelInfo
          FFI.LogLevel 4 -> Right LogLevelDebug
          FFI.LogLevel 5 -> Right LogLevelTrace
          l -> Left l
    case logLevel of
      Left l -> report $ E.SomeException $ RustlsUnknownLogLevel l
      Right logLevel -> do
        msg <- strToText rustlsLogParamsMessage
        cb logLevel msg `E.catch` report
  where
    report = reportError . E.SomeException . RustlsLogException

newConnection ::
  (Backend b) =>
  b ->
  ForeignPtr config ->
  Maybe LogCallback ->
  (Ptr config -> Ptr (Ptr FFI.Connection) -> IO FFI.Result) ->
  Acquire (Connection side)
newConnection backend configPtr logCallback connectionNew =
  mkAcquire acquire release
  where
    acquire = do
      conn <-
        alloca \connPtrPtr ->
          withForeignPtr configPtr \cfgPtr -> liftIO do
            rethrowR =<< connectionNew cfgPtr connPtrPtr
            peek connPtrPtr
      ioMsgReq <- newEmptyMVar
      ioMsgRes <- newEmptyMVar
      lenPtr <- malloc
      readWriteCallback <- FFI.mkReadWriteCallback \_ud buf len iPtr -> do
        putMVar ioMsgRes $ UsingBuffer buf len iPtr
        Done ioResult <- takeMVar ioMsgReq
        pure ioResult
      let freeCallback = freeHaskellFunPtr readWriteCallback
          interact = forever do
            Request readOrWrite <- takeMVar ioMsgReq
            let readOrWriteTls = case readOrWrite of
                  Read -> FFI.connectionReadTls
                  Write -> FFI.connectionWriteTls
            _ <- readOrWriteTls conn readWriteCallback nullPtr lenPtr
            putMVar ioMsgRes DoneFFI
      interactThread <- forkFinally interact (const freeCallback)
      for_ logCallback $ FFI.connectionSetLogCallback conn . unLogCallback
      Connection <$> newMVar Connection' {..}
    release (Connection c) = do
      Just Connection' {..} <- tryTakeMVar c
      FFI.connectionFree conn
      free lenPtr
      killThread interactThread

-- | Initialize a TLS connection as a client.
newClientConnection ::
  (Backend b) =>
  b ->
  ClientConfig ->
  -- | Hostname.
  Text ->
  Acquire (Connection Client)
newClientConnection b ClientConfig {..} hostname =
  newConnection b clientConfigPtr clientConfigLogCallback \configPtr connPtrPtr ->
    withCString (T.unpack hostname) \hostnamePtr ->
      FFI.clientConnectionNew configPtr hostnamePtr connPtrPtr

-- | Initialize a TLS connection as a server.
newServerConnection ::
  (Backend b) =>
  b ->
  ServerConfig ->
  Acquire (Connection Server)
newServerConnection b ServerConfig {..} =
  newConnection b serverConfigPtr serverConfigLogCallback FFI.serverConnectionNew

-- | Ensure that the connection is handshaked. It is only necessary to call this
-- if you want to obtain connection information. You can do so by providing a
-- 'HandshakeQuery'.
--
-- >>> :{
-- getALPNAndTLSVersion ::
--   MonadIO m =>
--   Connection side ->
--   m (Maybe ALPNProtocol, TLSVersion)
-- getALPNAndTLSVersion conn =
--   handshake conn $ (,) <$> getALPNProtocol <*> getTLSVersion
-- :}
handshake :: (MonadIO m) => Connection side -> HandshakeQuery side a -> m a
handshake conn (HandshakeQuery query) = liftIO do
  withConnection conn \c -> do
    runTLS c TLSHandshake
    runReaderT query c

-- | Get the negotiated ALPN protocol, if any.
getALPNProtocol :: HandshakeQuery side (Maybe ALPNProtocol)
getALPNProtocol = handshakeQuery \Connection' {conn, lenPtr} ->
  alloca \bufPtrPtr -> do
    FFI.connectionGetALPNProtocol conn bufPtrPtr lenPtr
    bufPtr <- peek bufPtrPtr
    len <- peek lenPtr
    !alpn <- B.packCStringLen (castPtr bufPtr, cSizeToInt len)
    pure $ if B.null alpn then Nothing else Just $ ALPNProtocol alpn

-- | Get the negotiated TLS protocol version.
getTLSVersion :: HandshakeQuery side TLSVersion
getTLSVersion = handshakeQuery \Connection' {conn} -> do
  !ver <- FFI.connectionGetProtocolVersion conn
  when (unTLSVersion ver == 0) $
    fail "internal rustls error: no protocol version negotiated"
  pure ver

-- | Get the negotiated cipher suite.
getCipherSuite :: HandshakeQuery side CipherSuite
getCipherSuite = handshakeQuery \Connection' {conn} -> do
  !cipherSuite <- FFI.connectionGetNegotiatedCipherSuite conn
  when (cipherSuite == nullPtr) $
    fail "internal rustls error: no cipher suite negotiated"
  pure $ CipherSuite cipherSuite

-- | Get the SNI hostname set by the client, if any.
getSNIHostname :: HandshakeQuery Server (Maybe Text)
getSNIHostname = handshakeQuery \Connection' {conn, lenPtr} ->
  let go n = allocaBytes (cSizeToInt n) \bufPtr -> do
        res <- FFI.serverConnectionGetSNIHostname conn bufPtr n lenPtr
        if res == FFI.resultInsufficientSize
          then go (2 * n)
          else do
            rethrowR res
            len <- peek lenPtr
            !sni <- T.peekCStringLen (castPtr bufPtr, cSizeToInt len)
            pure $ if T.null sni then Nothing else Just sni
   in go 16

-- | A DER-encoded certificate.
newtype DERCertificate = DERCertificate {unDERCertificate :: ByteString}
  deriving stock (Show, Eq, Ord, Generic)

-- | Get the @i@-th certificate provided by the peer.
--
-- Index @0@ is the end entity certificate. Higher indices are certificates in
-- the chain. Requesting an index higher than what is available returns
-- 'Nothing'.
getPeerCertificate :: CSize -> HandshakeQuery side (Maybe DERCertificate)
getPeerCertificate i = handshakeQuery \Connection' {conn, lenPtr} -> do
  certPtr <- FFI.connectionGetPeerCertificate conn i
  if certPtr == nullPtr
    then pure Nothing
    else alloca \bufPtrPtr -> do
      rethrowR =<< FFI.certificateGetDER certPtr bufPtrPtr lenPtr
      bufPtr <- peek bufPtrPtr
      len <- cSizeToInt <$> peek lenPtr
      !bs <- B.packCStringLen (castPtr bufPtr, len)
      pure $ Just $ DERCertificate bs

-- | Send a @close_notify@ warning alert. This informs the peer that the
-- connection is being closed.
sendCloseNotify :: (MonadIO m) => Connection side -> m ()
sendCloseNotify conn = liftIO $
  withConnection conn \c@Connection' {conn} -> do
    FFI.connectionSendCloseNotify conn
    runTLS c TLSWrite

-- | Read data from the Rustls 'Connection' into the given buffer.
readPtr :: (MonadIO m) => Connection side -> Ptr Word8 -> CSize -> m CSize
readPtr conn buf len = liftIO $
  withConnection conn \c@Connection' {..} -> do
    runTLS c TLSWrite
    runTLS c TLSRead
    rethrowR =<< FFI.connectionRead conn buf len lenPtr
    peek lenPtr

-- | Read data from the Rustls 'Connection' into a 'ByteString'. The result will
-- not be longer than the given length.
readBS ::
  (MonadIO m) =>
  Connection side ->
  -- | Maximum result length. Note that a buffer of this size will be allocated.
  Int ->
  m ByteString
readBS conn maxLen = liftIO $
  BI.createAndTrim maxLen \buf ->
    cSizeToInt <$> readPtr conn buf (intToCSize maxLen)

-- | Write data to the Rustls 'Connection' from the given buffer.
writePtr :: (MonadIO m) => Connection side -> Ptr Word8 -> CSize -> m CSize
writePtr conn buf len = liftIO $
  withConnection conn \c@Connection' {..} -> do
    rethrowR =<< FFI.connectionWrite conn buf len lenPtr
    runTLS c TLSWrite
    peek lenPtr

-- | Write a 'ByteString' to the Rustls 'Connection'.
writeBS :: (MonadIO m) => Connection side -> ByteString -> m ()
writeBS conn bs = liftIO $ BU.unsafeUseAsCStringLen bs go
  where
    go (buf, len) = do
      written <- cSizeToInt <$> writePtr conn (castPtr buf) (intToCSize len)
      when (written < len) $
        go (buf `plusPtr` len, len - written)
