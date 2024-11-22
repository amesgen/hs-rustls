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
-- Suppose you have already opened a 'Network.Socket.Socket' to @example.org@,
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
--     Rustls.buildClientConfig =<< Rustls.defaultClientConfigBuilder
--   let backend = Rustls.mkSocketBackend socket
--       newConnection =
--         Rustls.newClientConnection backend clientConfig "example.org"
--   withAcquire newConnection $ \conn -> do
--     Rustls.writeBS conn "GET /"
--     recv <- Rustls.readBS conn 1000 -- max number of bytes to read
--     print recv
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
    ServerCertVerifier (..),

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
    ClientCertVerifierPolicy (..),

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
    getNegotiatedCipherSuite,
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
    mkSocketBackend,
    mkByteStringBackend,

    -- ** Crypto provider
    CryptoProvider,
    getDefaultCryptoProvider,
    setCryptoProviderCipherSuites,
    cryptoProviderCipherSuites,
    cryptoProviderTLSVersions,

    -- ** Types
    ALPNProtocol (..),
    PEMCertificates (..),
    PEMCertificateParsing (..),
    CertifiedKey (..),
    DERCertificate (..),
    CertificateRevocationList (..),
    TLSVersion (TLS12, TLS13, unTLSVersion),
    CipherSuite (..),
    NegotiatedCipherSuite (..),

    -- ** Exceptions
    RustlsException,
    isCertError,
    RustlsLogException (..),
  )
where

import Control.Concurrent (forkFinally, killThread)
import Control.Concurrent.MVar
import Control.Exception qualified as E
import Control.Monad (forever, void, when)
import Control.Monad.Except (MonadError (..), liftEither)
import Control.Monad.IO.Class
import Control.Monad.Trans.Cont
import Control.Monad.Trans.Reader
import Data.Acquire
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Internal qualified as BI
import Data.ByteString.Unsafe qualified as BU
import Data.Coerce
import Data.Containers.ListUtils (nubOrd)
import Data.Foldable (for_, toList)
import Data.List.NonEmpty (NonEmpty)
import Data.List.NonEmpty qualified as NE
import Data.Set qualified as Set
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Foreign qualified as T
import Data.Traversable (for)
import Data.Word
import Foreign hiding (void)
import Foreign.C
import GHC.Conc (reportError)
import GHC.Generics (Generic)
import Rustls.Internal
import Rustls.Internal.FFI (ConstPtr (..), TLSVersion (..))
import Rustls.Internal.FFI qualified as FFI
import System.IO.Unsafe (unsafePerformIO)

-- $setup
-- >>> import Control.Monad.IO.Class
-- >>> import Data.Acquire

-- | Combined version string of Rustls and rustls-ffi, as well as the Rustls
-- cryptography provider.
--
-- >>> version
-- "rustls-ffi/0.14.1/rustls/0.23.18/aws-lc-rs"
version :: Text
version = unsafePerformIO $ alloca \strPtr -> do
  FFI.hsVersion strPtr
  strToText =<< peek strPtr
{-# NOINLINE version #-}

buildCryptoProvider :: Ptr FFI.CryptoProviderBuilder -> IO CryptoProvider
buildCryptoProvider builder = alloca \cryptoProviderPtr -> do
  rethrowR =<< FFI.cryptoProviderBuilderBuild builder cryptoProviderPtr
  ConstPtr cryptoProviderPtr <- peek cryptoProviderPtr
  CryptoProvider <$> newForeignPtr FFI.cryptoProviderFree cryptoProviderPtr

-- | Get the process-wide default Rustls cryptography provider.
getDefaultCryptoProvider :: (MonadIO m) => m CryptoProvider
getDefaultCryptoProvider = liftIO $ E.mask_ $ evalContT do
  builderPtr <- ContT alloca
  builder <-
    ContT $
      E.bracketOnError
        do
          -- This actually also sets the process-wide default crypto provider if
          -- not already set, which is a side effect.
          rethrowR =<< FFI.cryptoProviderBuilderNewFromDefault builderPtr
          peek builderPtr
        FFI.cryptoProviderBuilderFree
  liftIO $ buildCryptoProvider builder

-- | Create a derived 'CryptoProvider' by restricting the cipher suites to the
-- ones in the given list.
setCryptoProviderCipherSuites ::
  (MonadError RustlsException m) =>
  -- | Must be a subset of 'cryptoProviderCipherSuites'. Only the
  -- 'cipherSuiteID' is used.
  [CipherSuite] ->
  CryptoProvider ->
  m CryptoProvider
setCryptoProviderCipherSuites cipherSuites cryptoProvider =
  liftEither $ unsafePerformIO $ E.try $ E.mask_ $ evalContT do
    cryptoProviderPtr <- withCryptoProvider cryptoProvider
    builder <-
      ContT $
        E.bracketOnError
          (FFI.cryptoProviderBuilderNewWithBase cryptoProviderPtr)
          FFI.cryptoProviderBuilderFree

    let filteredCipherSuites =
          [ cipherSuitePtr
          | i <- [1 .. len],
            let cipherSuitePtr =
                  FFI.cryptoProviderCiphersuitesGet cryptoProviderPtr (i - 1)
                cipherSuiteID = FFI.supportedCipherSuiteGetSuite cipherSuitePtr,
            cipherSuiteID `Set.member` cipherSuiteIDs
          ]
          where
            len = FFI.cryptoProviderCiphersuitesLen cryptoProviderPtr
            cipherSuiteIDs = Set.fromList $ cipherSuiteID <$> cipherSuites

    (csPtr, csLen) <- ContT \cb -> withArrayLen filteredCipherSuites \len ptr ->
      cb (ConstPtr ptr, intToCSize len)
    liftIO $ rethrowR =<< FFI.cryptoProviderBuilderSetCipherSuites builder csPtr csLen

    liftIO $ buildCryptoProvider builder

withCryptoProvider :: CryptoProvider -> ContT a IO (ConstPtr FFI.CryptoProvider)
withCryptoProvider =
  fmap ConstPtr . ContT . withForeignPtr . unCryptoProvider

-- | Get the cipher suites supported by the given cryptography provider.
cryptoProviderCipherSuites :: CryptoProvider -> [CipherSuite]
cryptoProviderCipherSuites cryptoProvider = unsafePerformIO $ evalContT do
  cryptoProviderPtr <- withCryptoProvider cryptoProvider
  liftIO do
    let len = FFI.cryptoProviderCiphersuitesLen cryptoProviderPtr
    for [1 .. len] \i -> do
      let cipherSuitePtr = FFI.cryptoProviderCiphersuitesGet cryptoProviderPtr (i - 1)
          cipherSuiteID = FFI.supportedCipherSuiteGetSuite cipherSuitePtr
      cipherSuiteName <-
        alloca \strPtr -> do
          FFI.hsSupportedCipherSuiteGetName cipherSuitePtr strPtr
          strToText =<< peek strPtr
      cipherSuiteTLSVersion <-
        FFI.hsSupportedCiphersuiteProtocolVersion cipherSuitePtr
      pure CipherSuite {..}

-- | Get all TLS versions supported by at least one of the cipher suites
-- supported by the given cryptography provider.
cryptoProviderTLSVersions :: CryptoProvider -> [TLSVersion]
cryptoProviderTLSVersions =
  nubOrd
    . fmap cipherSuiteTLSVersion
    . cryptoProviderCipherSuites

-- | A 'ClientConfigBuilder' with good defaults, using the OS certificate store.
defaultClientConfigBuilder :: (MonadIO m) => m ClientConfigBuilder
defaultClientConfigBuilder = do
  cryptoProvider <- getDefaultCryptoProvider
  pure
    ClientConfigBuilder
      { clientConfigCryptoProvider = cryptoProvider,
        clientConfigServerCertVerifier = PlatformServerCertVerifier,
        clientConfigALPNProtocols = [],
        clientConfigEnableSNI = True,
        clientConfigCertifiedKeys = []
      }

withCertifiedKeys :: [CertifiedKey] -> ContT a IO (ConstPtr (ConstPtr FFI.CertifiedKey), CSize)
withCertifiedKeys certifiedKeys = do
  certKeys <- for certifiedKeys withCertifiedKey
  ContT \cb -> withArrayLen certKeys \len ptr -> cb (ConstPtr ptr, intToCSize len)
  where
    withCertifiedKey CertifiedKey {..} = do
      (certPtr, certLen) <- ContT $ BU.unsafeUseAsCStringLen certificateChain
      (privPtr, privLen) <- ContT $ BU.unsafeUseAsCStringLen privateKey
      certKeyPtr <- ContT alloca
      liftIO do
        rethrowR
          =<< FFI.certifiedKeyBuild
            (ConstPtr $ castPtr certPtr)
            (intToCSize certLen)
            (ConstPtr $ castPtr privPtr)
            (intToCSize privLen)
            certKeyPtr
        peek certKeyPtr

withALPNProtocols :: [ALPNProtocol] -> ContT a IO (ConstPtr FFI.SliceBytes, CSize)
withALPNProtocols bss = do
  bsPtrs <- for (coerce bss) withSliceBytes
  ContT \cb -> withArrayLen bsPtrs \len bsPtr -> cb (ConstPtr bsPtr, intToCSize len)
  where
    withSliceBytes bs = do
      (buf, len) <- ContT $ BU.unsafeUseAsCStringLen bs
      pure $ FFI.SliceBytes (castPtr buf) (intToCSize len)

configBuilderNew ::
  ( ConstPtr FFI.CryptoProvider ->
    ConstPtr TLSVersion ->
    CSize ->
    Ptr (Ptr configBuilder) ->
    IO FFI.Result
  ) ->
  CryptoProvider ->
  IO (Ptr configBuilder)
configBuilderNew configBuilderNewCustom cryptoProvider = evalContT do
  cryptoProviderPtr <- withCryptoProvider cryptoProvider
  builderPtr <- ContT alloca
  (tlsVersionsLen, tlsVersionsPtr) <-
    ContT \cb -> withArrayLen (cryptoProviderTLSVersions cryptoProvider) \len ptr ->
      cb (intToCSize len, ConstPtr ptr)
  liftIO do
    rethrowR
      =<< configBuilderNewCustom
        cryptoProviderPtr
        tlsVersionsPtr
        tlsVersionsLen
        builderPtr
    peek builderPtr

withRootCertStore :: [PEMCertificates] -> ContT a IO (ConstPtr FFI.RootCertStore)
withRootCertStore certs = do
  storeBuilder <-
    ContT $ E.bracket FFI.rootCertStoreBuilderNew FFI.rootCertStoreBuilderFree
  let isStrict :: PEMCertificateParsing -> CBool
      isStrict =
        fromBool @CBool . \case
          PEMCertificateParsingStrict -> True
          PEMCertificateParsingLax -> False
  for_ certs \case
    PEMCertificatesInMemory bs parsing -> do
      (buf, len) <- ContT $ BU.unsafeUseAsCStringLen bs
      liftIO $
        rethrowR
          =<< FFI.rootCertStoreBuilderAddPem
            storeBuilder
            (ConstPtr $ castPtr buf)
            (intToCSize len)
            (isStrict parsing)
    PemCertificatesFromFile path parsing -> do
      pathPtr <- ContT $ withCString path
      liftIO $
        rethrowR
          =<< FFI.rootCertStoreBuilderLoadRootsFromFile
            storeBuilder
            (ConstPtr pathPtr)
            (isStrict parsing)
  storePtr <- ContT alloca
  let buildRootCertStore = do
        liftIO $ rethrowR =<< FFI.rootCertStoreBuilderBuild storeBuilder storePtr
        peek storePtr
  ContT $ E.bracket buildRootCertStore FFI.rootCertStoreFree

-- | Build a 'ClientConfigBuilder' into a 'ClientConfig'.
--
-- This is a relatively expensive operation, so it is a good idea to share one
-- 'ClientConfig' when creating multiple 'Connection's.
buildClientConfig :: (MonadIO m) => ClientConfigBuilder -> m ClientConfig
buildClientConfig ClientConfigBuilder {..} = liftIO . E.mask_ $ evalContT do
  builder <-
    ContT $
      E.bracketOnError
        ( configBuilderNew
            FFI.clientConfigBuilderNewCustom
            clientConfigCryptoProvider
        )
        FFI.clientConfigBuilderFree

  cryptoProviderPtr <- withCryptoProvider clientConfigCryptoProvider

  scv <- case clientConfigServerCertVerifier of
    PlatformServerCertVerifier ->
      withCryptoProvider clientConfigCryptoProvider
        >>= liftIO . FFI.platformServerCertVerifierWithProvider
    ServerCertVerifier {..} -> do
      rootCertStore <- withRootCertStore $ toList serverCertVerifierCertificates
      scvb <-
        ContT $
          E.bracket
            (FFI.webPkiServerCertVerifierBuilderNewWithProvider cryptoProviderPtr rootCertStore)
            FFI.webPkiServerCertVerifierBuilderFree
      crls :: [CStringLen] <-
        for serverCertVerifierCRLs $
          ContT . BU.unsafeUseAsCStringLen . unCertificateRevocationList
      liftIO $ for_ crls \(ptr, len) ->
        FFI.webPkiServerCertVerifierBuilderAddCrl
          scvb
          (ConstPtr (castPtr ptr))
          (intToCSize len)
      scvPtr <- ContT alloca
      let buildScv = do
            rethrowR =<< FFI.webPkiServerCertVerifierBuilderBuild scvb scvPtr
            peek scvPtr
      ContT $ E.bracket buildScv FFI.serverCertVerifierFree
  liftIO $ FFI.clientConfigBuilderSetServerVerifier builder (ConstPtr scv)

  (alpnPtr, len) <- withALPNProtocols clientConfigALPNProtocols
  liftIO $ rethrowR =<< FFI.clientConfigBuilderSetALPNProtocols builder alpnPtr len

  liftIO $
    FFI.clientConfigBuilderSetEnableSNI builder (fromBool @CBool clientConfigEnableSNI)

  (ptr, len) <- withCertifiedKeys clientConfigCertifiedKeys
  liftIO $ rethrowR =<< FFI.clientConfigBuilderSetCertifiedKey builder ptr len

  let clientConfigLogCallback = Nothing

  clientConfigPtrPtr <- ContT alloca
  liftIO do
    rethrowR =<< FFI.clientConfigBuilderBuild builder clientConfigPtrPtr
    clientConfigPtr <-
      newForeignPtr FFI.clientConfigFree . unConstPtr
        =<< peek clientConfigPtrPtr
    pure ClientConfig {..}

-- | Build a 'ServerConfigBuilder' into a 'ServerConfig'.
--
-- This is a relatively expensive operation, so it is a good idea to share one
-- 'ServerConfig' when creating multiple 'Connection's.
buildServerConfig :: (MonadIO m) => ServerConfigBuilder -> m ServerConfig
buildServerConfig ServerConfigBuilder {..} = liftIO . E.mask_ $ evalContT do
  builder <-
    ContT $
      E.bracketOnError
        ( configBuilderNew
            FFI.serverConfigBuilderNewCustom
            serverConfigCryptoProvider
        )
        FFI.serverConfigBuilderFree

  cryptoProviderPtr <- withCryptoProvider serverConfigCryptoProvider

  (alpnPtr, len) <- withALPNProtocols serverConfigALPNProtocols
  liftIO $ rethrowR =<< FFI.serverConfigBuilderSetALPNProtocols builder alpnPtr len

  liftIO $
    rethrowR
      =<< FFI.serverConfigBuilderSetIgnoreClientOrder
        builder
        (fromBool @CBool serverConfigIgnoreClientOrder)

  (ptr, len) <- withCertifiedKeys (NE.toList serverConfigCertifiedKeys)
  liftIO $ rethrowR =<< FFI.serverConfigBuilderSetCertifiedKeys builder ptr len

  for_ serverConfigClientCertVerifier \ClientCertVerifier {..} -> do
    roots <- withRootCertStore $ NE.toList clientCertVerifierCertificates
    ccvb <-
      ContT $
        E.bracket
          (FFI.webPkiClientCertVerifierBuilderNewWithProvider cryptoProviderPtr roots)
          FFI.webPkiClientCertVerifierBuilderFree
    crls :: [CStringLen] <-
      for clientCertVerifierCRLs $
        ContT . BU.unsafeUseAsCStringLen . unCertificateRevocationList
    liftIO do
      case clientCertVerifierPolicy of
        AllowAnyAuthenticatedClient -> pure ()
        AllowAnyAnonymousOrAuthenticatedClient ->
          rethrowR =<< FFI.webPkiClientCertVerifierBuilderAllowUnauthenticated ccvb
      for_ crls \(ptr, len) ->
        FFI.webPkiClientCertVerifierBuilderAddCrl
          ccvb
          (ConstPtr (castPtr ptr))
          (intToCSize len)
    ccvPtr <- ContT alloca
    let buildCcv = do
          rethrowR =<< FFI.webPkiClientCertVerifierBuilderBuild ccvb ccvPtr
          peek ccvPtr
    ccv <- ContT $ E.bracket buildCcv FFI.clientCertVerifierFree
    liftIO $ FFI.serverConfigBuilderSetClientVerifier builder (ConstPtr ccv)

  serverConfigPtrPtr <- ContT alloca
  liftIO do
    rethrowR =<< FFI.serverConfigBuilderBuild builder serverConfigPtrPtr
    serverConfigPtr <-
      newForeignPtr FFI.serverConfigFree . unConstPtr
        =<< peek serverConfigPtrPtr
    let serverConfigLogCallback = Nothing
    pure ServerConfig {..}

-- | A 'ServerConfigBuilder' with good defaults.
defaultServerConfigBuilder ::
  (MonadIO m) => NonEmpty CertifiedKey -> m ServerConfigBuilder
defaultServerConfigBuilder certifiedKeys = do
  cryptoProvider <- getDefaultCryptoProvider
  pure
    ServerConfigBuilder
      { serverConfigCryptoProvider = cryptoProvider,
        serverConfigCertifiedKeys = certifiedKeys,
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
  FFI.mkLogCallback \_ (ConstPtr logParamsPtr) -> ignoreExceptions do
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
  Backend ->
  ForeignPtr config ->
  Maybe LogCallback ->
  (ConstPtr config -> Ptr (Ptr FFI.Connection) -> IO FFI.Result) ->
  Acquire (Connection side)
newConnection backend configPtr logCallback connectionNew =
  mkAcquire acquire release
  where
    acquire = do
      conn <-
        alloca \connPtrPtr ->
          withForeignPtr configPtr \cfgPtr -> liftIO do
            rethrowR =<< connectionNew (ConstPtr cfgPtr) connPtrPtr
            peek connPtrPtr
      ioMsgReq <- newEmptyMVar
      ioMsgRes <- newEmptyMVar
      lenPtr <- malloc
      let readWriteCallback toBuf _ud buf len iPtr = do
            putMVar ioMsgRes $ UsingBuffer (toBuf buf) len iPtr
            Done ioResult <- takeMVar ioMsgReq
            pure ioResult
      readCallback <- FFI.mkReadCallback $ readWriteCallback id
      writeCallback <- FFI.mkWriteCallback $ readWriteCallback unConstPtr
      let freeCallback = do
            freeHaskellFunPtr readCallback
            freeHaskellFunPtr writeCallback
          interact = forever do
            Request readOrWrite <- takeMVar ioMsgReq
            let readOrWriteTls = case readOrWrite of
                  Read -> flip FFI.connectionReadTls readCallback
                  Write -> flip FFI.connectionWriteTls writeCallback
            _ <- readOrWriteTls conn nullPtr lenPtr
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
  Backend ->
  ClientConfig ->
  -- | Hostname.
  Text ->
  Acquire (Connection Client)
newClientConnection b ClientConfig {..} hostname =
  newConnection b clientConfigPtr clientConfigLogCallback \configPtr connPtrPtr ->
    T.withCString hostname \hostnamePtr ->
      FFI.clientConnectionNew configPtr (ConstPtr hostnamePtr) connPtrPtr

-- | Initialize a TLS connection as a server.
newServerConnection ::
  Backend ->
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
    _ <- completePriorIO c
    runReaderT query c

-- | Get the negotiated ALPN protocol, if any.
getALPNProtocol :: HandshakeQuery side (Maybe ALPNProtocol)
getALPNProtocol = handshakeQuery \Connection' {conn, lenPtr} ->
  alloca \bufPtrPtr -> do
    FFI.connectionGetALPNProtocol (ConstPtr conn) bufPtrPtr lenPtr
    ConstPtr bufPtr <- peek bufPtrPtr
    len <- peek lenPtr
    !alpn <- B.packCStringLen (castPtr bufPtr, cSizeToInt len)
    pure $ if B.null alpn then Nothing else Just $ ALPNProtocol alpn

-- | Get the negotiated TLS protocol version.
getTLSVersion :: HandshakeQuery side TLSVersion
getTLSVersion = handshakeQuery \Connection' {conn} -> do
  !ver <- FFI.connectionGetProtocolVersion (ConstPtr conn)
  when (unTLSVersion ver == 0) $
    fail "internal rustls error: no protocol version negotiated"
  pure ver

-- | Get the negotiated cipher suite.
getNegotiatedCipherSuite :: HandshakeQuery side NegotiatedCipherSuite
getNegotiatedCipherSuite = handshakeQuery \Connection' {conn} -> do
  negotiatedCipherSuiteID <-
    FFI.connectionGetNegotiatedCipherSuite (ConstPtr conn)
  when (negotiatedCipherSuiteID == 0) $
    fail "internal rustls error: no cipher suite negotiated"

  negotiatedCipherSuiteName <- alloca \strPtr -> do
    FFI.connectionGetNegotiatedCipherSuiteName (ConstPtr conn) strPtr
    strToText =<< peek strPtr
  when (T.null negotiatedCipherSuiteName) $
    fail "internal rustls error: no cipher suite negotiated"

  pure NegotiatedCipherSuite {..}

-- | Get the SNI hostname set by the client, if any.
getSNIHostname :: HandshakeQuery Server (Maybe Text)
getSNIHostname = handshakeQuery \Connection' {conn, lenPtr} ->
  let go n = allocaBytes (cSizeToInt n) \bufPtr -> do
        res <- FFI.serverConnectionGetSNIHostname (ConstPtr conn) bufPtr n lenPtr
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
  certPtr <- FFI.connectionGetPeerCertificate (ConstPtr conn) i
  if certPtr == ConstPtr nullPtr
    then pure Nothing
    else alloca \bufPtrPtr -> do
      rethrowR =<< FFI.certificateGetDER certPtr bufPtrPtr lenPtr
      ConstPtr bufPtr <- peek bufPtrPtr
      len <- cSizeToInt <$> peek lenPtr
      !bs <- B.packCStringLen (castPtr bufPtr, len)
      pure $ Just $ DERCertificate bs

-- | Send a @close_notify@ warning alert. This informs the peer that the
-- connection is being closed.
sendCloseNotify :: (MonadIO m) => Connection side -> m ()
sendCloseNotify conn = liftIO $
  withConnection conn \c@Connection' {conn} -> do
    FFI.connectionSendCloseNotify conn
    void $ completeIO c

-- | Read data from the Rustls 'Connection' into the given buffer.
readPtr :: (MonadIO m) => Connection side -> Ptr Word8 -> CSize -> m CSize
readPtr conn buf len = liftIO $
  withConnection conn \c@Connection' {..} -> do
    completePriorIO c
    loopWhileTrue $
      getWantsRead c >>= \case
        True -> (NotEOF ==) <$> completeIO c
        False -> pure False
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
    completePriorIO c
    rethrowR =<< FFI.connectionWrite conn buf len lenPtr
    _ <- completeIO c
    peek lenPtr

-- | Write a 'ByteString' to the Rustls 'Connection'.
writeBS :: (MonadIO m) => Connection side -> ByteString -> m ()
writeBS conn bs = liftIO $ BU.unsafeUseAsCStringLen bs go
  where
    go (buf, len) = do
      written <- cSizeToInt <$> writePtr conn (castPtr buf) (intToCSize len)
      when (written < len) $
        go (buf `plusPtr` len, len - written)
