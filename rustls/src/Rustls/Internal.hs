{-# OPTIONS_GHC -Wno-missing-export-lists #-}

-- | Internal module, not subject to PVP.
module Rustls.Internal where

import Control.Concurrent (ThreadId)
import Control.Concurrent.MVar
import Control.Exception qualified as E
import Control.Monad (when)
import Control.Monad.Trans.Reader
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Unsafe qualified as BU
import Data.Coerce (coerce)
import Data.Function (on)
import Data.Functor (void)
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Foreign qualified as T
import Foreign hiding (void)
import Foreign.C
import GHC.Generics (Generic)
import Network.Socket qualified as NS
import Rustls.Internal.FFI (ConstPtr (..))
import Rustls.Internal.FFI qualified as FFI
import System.IO.Unsafe (unsafePerformIO)

-- | An ALPN protocol ID. See
-- <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>
-- for a list of registered IDs.
newtype ALPNProtocol = ALPNProtocol {unALPNProtocol :: ByteString}
  deriving stock (Show, Eq, Ord, Generic)

-- | A TLS cipher suite supported by Rustls.
newtype CipherSuite = CipherSuite (ConstPtr FFI.SupportedCipherSuite)

-- | Get the IANA value from a cipher suite. The bytes are interpreted in network order.
--
-- See <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4> for a list.
cipherSuiteID :: CipherSuite -> Word16
cipherSuiteID (CipherSuite cipherSuitePtr) =
  FFI.supportedCipherSuiteGetSuite cipherSuitePtr

instance Eq CipherSuite where
  (==) = (==) `on` cipherSuiteID

instance Ord CipherSuite where
  compare = compare `on` cipherSuiteID

-- | Get the text representation of a cipher suite.
showCipherSuite :: CipherSuite -> Text
showCipherSuite (CipherSuite cipherSuitePtr) = unsafePerformIO $
  alloca \strPtr -> do
    FFI.hsSupportedCipherSuiteGetName cipherSuitePtr strPtr
    strToText =<< peek strPtr

instance Show CipherSuite where
  show = T.unpack . showCipherSuite

-- | Rustls client config builder.
data ClientConfigBuilder = ClientConfigBuilder
  { -- | The server certificate verifier.
    clientConfigServerCertVerifier :: ServerCertVerifier,
    -- | Supported 'FFI.TLSVersion's. When empty, good defaults are used.
    clientConfigTLSVersions :: [FFI.TLSVersion],
    -- | Supported 'CipherSuite's in order of preference. When empty, good
    -- defaults are used.
    clientConfigCipherSuites :: [CipherSuite],
    -- | ALPN protocols.
    clientConfigALPNProtocols :: [ALPNProtocol],
    -- | Whether to enable Server Name Indication. Defaults to 'True'.
    clientConfigEnableSNI :: Bool,
    -- | List of 'CertifiedKey's for client authentication.
    --
    -- Clients that want to support both ECDSA and RSA certificates will want
    -- the ECDSA to go first in the list.
    clientConfigCertifiedKeys :: [CertifiedKey]
  }
  deriving stock (Show, Generic)

-- | How to verify TLS server certificates.
data ServerCertVerifier = ServerCertVerifier
  { -- | Certificates used to verify TLS server certificates.
    serverCertVerifierCertificates :: NonEmpty PEMCertificates,
    -- | List of certificate revocation lists used to verify TLS server
    -- certificates.
    serverCertVerifierCRLs :: [CertificateRevocationList]
  }
  deriving stock (Show, Generic)

-- | A source of PEM-encoded certificates.
data PEMCertificates
  = -- | In-memory PEM-encoded certificates.
    PEMCertificatesInMemory ByteString PEMCertificateParsing
  | -- |  Fetch PEM-encoded root certificates from a file.
    PemCertificatesFromFile FilePath PEMCertificateParsing
  deriving stock (Show, Generic)

-- | Parsing mode for PEM-encoded certificates.
data PEMCertificateParsing
  = -- | Fail if syntactically invalid.
    PEMCertificateParsingStrict
  | -- | Ignore if syntactically invalid.
    --
    -- This may be useful on systems that have syntactically invalid root
    -- certificates.
    PEMCertificateParsingLax
  deriving stock (Show, Eq, Ord, Enum, Bounded, Generic)

-- | A complete chain of certificates plus a private key for the leaf certificate.
data CertifiedKey = CertifiedKey
  { -- | PEM-encoded certificate chain.
    certificateChain :: ByteString,
    -- | PEM-encoded private key.
    privateKey :: ByteString
  }
  deriving stock (Generic)

instance Show CertifiedKey where
  show _ = "CertifiedKey"

-- | Assembled configuration for a Rustls client connection.
data ClientConfig = ClientConfig
  { clientConfigPtr :: ForeignPtr FFI.ClientConfig,
    -- | A logging callback.
    --
    -- Note that this is a record selector, so you can use it as a setter:
    --
    -- >>> :{
    -- setLogCallback :: LogCallback -> ClientConfig -> ClientConfig
    -- setLogCallback logCallback clientConfig =
    --   clientConfig { clientConfigLogCallback = Just logCallback }
    -- :}
    clientConfigLogCallback :: Maybe LogCallback
  }

-- | How to verify TLS client certificates.
data ClientCertVerifier = ClientCertVerifier
  { -- | Which client connections are allowed.
    clientCertVerifierPolicy :: ClientCertVerifierPolicy,
    -- | Certificates used to verify TLS client certificates.
    clientCertVerifierCertificates :: NonEmpty PEMCertificates,
    -- | List of certificate revocation lists used to verify TLS client
    -- certificates.
    clientCertVerifierCRLs :: [CertificateRevocationList]
  }
  deriving stock (Show, Generic)

-- | Which client connections are allowed by a 'ClientCertVerifier'.
data ClientCertVerifierPolicy
  = -- | Allow any authenticated client (i.e. offering a trusted certificate),
    -- and reject clients offering none.
    AllowAnyAuthenticatedClient
  | -- | Allow any authenticated client (i.e. offering a trusted certificate),
    -- but also allow clients offering none.
    AllowAnyAnonymousOrAuthenticatedClient
  deriving stock (Show, Eq, Ord, Enum, Bounded, Generic)

-- | One or more PEM-encoded certificate revocation lists (CRL).
newtype CertificateRevocationList = CertificateRevocationList
  { unCertificateRevocationList :: ByteString
  }
  deriving stock (Show, Generic)

-- | Rustls client config builder.
data ServerConfigBuilder = ServerConfigBuilder
  { -- | List of 'CertifiedKey's.
    serverConfigCertifiedKeys :: NonEmpty CertifiedKey,
    -- | Supported 'FFI.TLSVersion's. When empty, good defaults are
    -- used.
    serverConfigTLSVersions :: [FFI.TLSVersion],
    -- | Supported 'CipherSuite's in order of preference. When empty, good
    -- defaults are used.
    serverConfigCipherSuites :: [CipherSuite],
    -- | ALPN protocols.
    serverConfigALPNProtocols :: [ALPNProtocol],
    -- | Ignore the client's ciphersuite order. Defaults to 'False'.
    serverConfigIgnoreClientOrder :: Bool,
    -- | Optionally, a client cert verifier.
    serverConfigClientCertVerifier :: Maybe ClientCertVerifier
  }
  deriving stock (Show, Generic)

-- | Assembled configuration for a Rustls server connection.
data ServerConfig = ServerConfig
  { serverConfigPtr :: ForeignPtr FFI.ServerConfig,
    -- | A logging callback.
    --
    -- Note that this is a record selector, so you can use it as a setter:
    --
    -- >>> :{
    -- setLogCallback :: LogCallback -> ServerConfig -> ServerConfig
    -- setLogCallback logCallback serverConfig =
    --   serverConfig { serverConfigLogCallback = Just logCallback }
    -- :}
    serverConfigLogCallback :: Maybe LogCallback
  }

-- | Rustls log level.
data LogLevel
  = LogLevelError
  | LogLevelWarn
  | LogLevelInfo
  | LogLevelDebug
  | LogLevelTrace
  deriving stock (Show, Eq, Ord, Enum, Bounded, Generic)

-- | A Rustls connection logging callback.
newtype LogCallback = LogCallback {unLogCallback :: FunPtr FFI.LogCallback}

-- | A 'Monad' to get TLS connection information via 'Rustls.handshake'.
newtype HandshakeQuery (side :: Side) a = HandshakeQuery (ReaderT Connection' IO a)
  deriving newtype (Functor, Applicative, Monad)

type role HandshakeQuery nominal _

handshakeQuery :: (Connection' -> IO a) -> HandshakeQuery side a
handshakeQuery = coerce

-- | TLS exception thrown by Rustls.
--
-- Use 'E.displayException' for a human-friendly representation.
newtype RustlsException = RustlsException {rustlsErrorCode :: Word32}
  deriving stock (Show)

instance E.Exception RustlsException where
  displayException RustlsException {rustlsErrorCode} =
    unwords
      [ "Rustls error:",
        T.unpack (resultMsg (FFI.Result rustlsErrorCode)),
        "(" <> show rustlsErrorCode <> ")"
      ]

resultMsg :: FFI.Result -> Text
resultMsg r = unsafePerformIO $
  alloca \lenPtr -> allocaBytes (cSizeToInt msgLen) \buf -> do
    FFI.errorMsg r buf msgLen lenPtr
    len <- peek lenPtr
    T.peekCStringLen (buf, cSizeToInt len)
  where
    msgLen = 1024 -- a bit pessimistic?

-- | Checks if the given 'RustlsException' represents a certificate error.
isCertError :: RustlsException -> Bool
isCertError RustlsException {rustlsErrorCode} =
  toBool @CBool $ FFI.resultIsCertError (FFI.Result rustlsErrorCode)

rethrowR :: FFI.Result -> IO ()
rethrowR = \case
  r | r == FFI.resultOk -> mempty
  FFI.Result rustlsErrorCode ->
    E.throwIO $ RustlsException rustlsErrorCode

-- | Wrapper for exceptions thrown in a 'LogCallback'.
newtype RustlsLogException = RustlsLogException E.SomeException
  deriving stock (Show)
  deriving anyclass (E.Exception)

data RustlsUnknownLogLevel = RustlsUnknownLogLevel FFI.LogLevel
  deriving stock (Show)
  deriving anyclass (E.Exception)

-- | Underlying data source for Rustls.
data Backend = Backend
  { -- | Read data from the backend into the given buffer.
    backendRead ::
      -- Target buffer pointer.
      Ptr Word8 ->
      -- Target buffer length.
      CSize ->
      -- Amount of bytes read.
      IO CSize,
    -- | Write data from the given buffer to the backend.
    backendWrite ::
      -- Source buffer pointer.
      Ptr Word8 ->
      -- Source buffer length.
      CSize ->
      -- Amount of bytes written.
      IO CSize
  }

mkSocketBackend :: NS.Socket -> Backend
mkSocketBackend s = Backend {..}
  where
    backendRead buf len =
      intToCSize <$> NS.recvBuf s buf (cSizeToInt len)
    backendWrite buf len =
      intToCSize <$> NS.sendBuf s buf (cSizeToInt len)

-- | An in-memory 'Backend'.
mkByteStringBackend ::
  -- | Read a 'ByteString' with the given max length.
  --
  -- This will silently truncate 'ByteString's which are too long.
  (Int -> IO ByteString) ->
  -- | Write a 'ByteString'.
  (ByteString -> IO ()) ->
  Backend
mkByteStringBackend bsbRead bsbWrite = Backend {..}
  where
    backendRead buf len = do
      bs <- bsbRead (cSizeToInt len)
      BU.unsafeUseAsCStringLen bs \(bsPtr, bsLen) -> do
        let copyLen = bsLen `min` cSizeToInt len
        copyBytes buf (castPtr bsPtr) copyLen
        pure $ intToCSize copyLen
    backendWrite buf len = do
      bsbWrite =<< B.packCStringLen (castPtr buf, cSizeToInt len)
      pure len

-- | Type-level indicator whether a 'Connection' is client- or server-side.
data Side = Client | Server

-- | A Rustls connection.
newtype Connection (side :: Side) = Connection (MVar Connection')

type role Connection nominal

data Connection' = Connection'
  { conn :: Ptr FFI.Connection,
    backend :: Backend,
    lenPtr :: Ptr CSize,
    ioMsgReq :: MVar IOMsgReq,
    ioMsgRes :: MVar IOMsgRes,
    interactThread :: ThreadId
  }

withConnection :: Connection side -> (Connection' -> IO a) -> IO a
withConnection (Connection c) = withMVar c

data ReadOrWrite = Read | Write

-- GHC will delay async exceptions to (non-interruptible) FFI calls until they
-- finish. In particular, this means that when a (safe) FFI call invokes a
-- Haskell callback, it is uncancelable. As usages of this library will most
-- likely involve actual I/O (which really should be able to be cancelled), we
-- invoke the respective FFI functions (which will themselves then call back
-- into Haskell) in a separate thread, and interact with it via message passing
-- (see the 'IOMsgReq' and 'IOMsgRes' types).

-- | Messages sent to the background thread.
data IOMsgReq
  = -- | Request to start a read or a write FFI call from the background thread.
    -- It should respond with 'UsingBuffer'.
    Request ReadOrWrite
  | -- | Notify the background thread that we are done interacting with the
    -- buffer.
    Done FFI.IOResult

-- | Messages sent from the background thread.
data IOMsgRes
  = -- | Reply with a buffer, either containing the read data, or awaiting a
    -- write to this buffer.
    UsingBuffer (Ptr Word8) CSize (Ptr CSize)
  | -- | Notify that the FFI call finished.
    DoneFFI

interactTLS :: Connection' -> ReadOrWrite -> IO CSize
interactTLS Connection' {..} readOrWrite = E.uninterruptibleMask \restore -> do
  putMVar ioMsgReq $ Request readOrWrite
  UsingBuffer buf len sizePtr <- takeMVar ioMsgRes
  size <-
    restore (readOrWriteBackend buf len)
      `E.onException` done FFI.ioResultErr
  poke sizePtr size
  done FFI.ioResultOk
  pure size
  where
    readOrWriteBackend = case readOrWrite of
      Read -> backendRead backend
      Write -> backendWrite backend
    done ioResult = do
      putMVar ioMsgReq $ Done ioResult
      DoneFFI <- takeMVar ioMsgRes
      pure ()

data IsEOF = IsEOF | NotEOF
  deriving stock (Show, Eq)

-- | Helper function, see @complete_io@ from rustls.
--
-- <https://github.com/rustls/rustls/blob/v/0.23.4/rustls/src/conn.rs#L544>
completeIO :: Connection' -> IO IsEOF
completeIO c@Connection' {..} = go NotEOF
  where
    go eof = do
      untilHandshaked <- getIsHandshaking c
      atLeastOneWrite <- getWantsWrite c

      loopWhileTrue runWrite

      if not untilHandshaked && atLeastOneWrite
        then pure eof
        else do
          wantsRead <- getWantsRead c
          eof <-
            if eof == NotEOF && wantsRead
              then do
                bytesRead <- interactTLS c Read
                pure if bytesRead == 0 then IsEOF else NotEOF
              else pure eof

          r <- FFI.connectionProcessNewPackets conn
          -- try to notify our peer that we encountered a TLS error
          when (r /= FFI.resultOk) $ ignoreSyncExceptions $ void runWrite
          rethrowR r

          stillHandshaking <- getIsHandshaking c
          finished <- case (untilHandshaked, stillHandshaking) of
            (True, False) -> not <$> getWantsWrite c
            (False, _) -> pure True
            (True, True) -> do
              when (eof == IsEOF) $ fail "rustls: unexpected eof"
              pure False
          if finished then pure eof else go eof

    runWrite = do
      wantsWrite <- getWantsWrite c
      when wantsWrite $ void $ interactTLS c Write
      pure wantsWrite

completePriorIO :: Connection' -> IO ()
completePriorIO c = do
  whenM (getIsHandshaking c) $ void $ completeIO c
  whenM (getWantsWrite c) $ void $ completeIO c

getIsHandshaking :: Connection' -> IO Bool
getIsHandshaking Connection' {conn} =
  toBool @CBool <$> FFI.connectionIsHandshaking (ConstPtr conn)

getWantsRead :: Connection' -> IO Bool
getWantsRead Connection' {conn} =
  toBool @CBool <$> FFI.connectionWantsRead (ConstPtr conn)

getWantsWrite :: Connection' -> IO Bool
getWantsWrite Connection' {conn} =
  toBool @CBool <$> FFI.connectionWantsWrite (ConstPtr conn)

-- utils

whenM :: (Monad m) => m Bool -> m () -> m ()
whenM cond action = cond >>= \case True -> action; False -> pure ()

loopWhileTrue :: (Monad m) => m Bool -> m ()
loopWhileTrue action = whenM action $ loopWhileTrue action

cSizeToInt :: CSize -> Int
cSizeToInt = fromIntegral
{-# INLINE cSizeToInt #-}

intToCSize :: Int -> CSize
intToCSize = fromIntegral
{-# INLINE intToCSize #-}

strToText :: FFI.Str -> IO Text
strToText (FFI.Str buf len) = T.peekCStringLen (buf, cSizeToInt len)

ignoreExceptions :: IO () -> IO ()
ignoreExceptions = void . E.try @E.SomeException

ignoreSyncExceptions :: IO () -> IO ()
ignoreSyncExceptions = E.handle \case
  (E.fromException -> Just e@(E.SomeAsyncException _)) -> E.throwIO e
  _ -> pure ()
