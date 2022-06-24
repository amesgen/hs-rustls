{-# OPTIONS_GHC -Wno-missing-export-lists #-}

-- | Internal module, not subject to PVP.
module Rustls.Internal where

import Control.Concurrent (ThreadId)
import Control.Concurrent.MVar
import qualified Control.Exception as E
import Control.Monad (when)
import Control.Monad.Trans.Reader
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as BU
import Data.Coerce (coerce)
import Data.Function (on)
import Data.Functor (void)
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Foreign as T
import Foreign hiding (void)
import Foreign.C
import GHC.Generics (Generic)
import qualified Network.Socket as NS
import qualified Rustls.Internal.FFI as FFI
import System.IO.Unsafe (unsafePerformIO)

-- | An ALPN protocol ID. See
-- <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>
-- for a list of registered IDs.
newtype ALPNProtocol = ALPNProtocol {unALPNProtocol :: ByteString}
  deriving stock (Show, Eq, Ord, Generic)

-- | A TLS cipher suite supported by Rustls.
newtype CipherSuite = CipherSuite (Ptr FFI.SupportedCipherSuite)

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
  { -- | Client root certificates.
    clientConfigRoots :: ClientRoots,
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

-- | How to look up root certificates.
data ClientRoots
  = -- | Fetch PEM-encoded root certificates from a file.
    ClientRootsFromFile FilePath
  | -- | Use in-memory PEM-encoded certificates.
    ClientRootsInMemory [PEMCertificates]
  deriving stock (Generic)

instance Show ClientRoots where
  show _ = "ClientRoots"

-- | In-memory PEM-encoded certificates.
data PEMCertificates
  = -- | Syntactically valid PEM-encoded certificates.
    PEMCertificatesStrict ByteString
  | -- | PEM-encoded certificates, ignored if syntactically invalid.
    --
    -- This may be useful on systems that have syntactically invalid root certificates.
    PEMCertificatesLax ByteString
  deriving stock (Show, Generic)

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
    -- | A logging callback. If it throws an exception, a note will be printed
    -- to stderr.
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
data ClientCertVerifier
  = -- | Root certificates used to verify TLS client certificates.
    ClientCertVerifier [PEMCertificates]
  | -- | Root certificates used to verify TLS client certificates if present,
    -- but does not reject clients which provide no certificate.
    ClientCertVerifierOptional [PEMCertificates]
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
    -- | A logging callback. If it throws an exception, a note will be printed
    -- to stderr.
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

-- | Underlying data sources for Rustls.
class Backend b where
  -- | Read data from the backend into the given buffer.
  backendRead ::
    b ->
    -- | Target buffer pointer.
    Ptr Word8 ->
    -- | Target buffer length.
    CSize ->
    -- | Amount of bytes read.
    IO CSize

  -- | Write data from the given buffer to the backend.
  backendWrite ::
    b ->
    -- | Source buffer pointer.
    Ptr Word8 ->
    -- | Source buffer length.
    CSize ->
    -- | Amount of bytes written.
    IO CSize

instance Backend NS.Socket where
  backendRead s buf len =
    intToCSize <$> NS.recvBuf s buf (cSizeToInt len)
  backendWrite s buf len =
    intToCSize <$> NS.sendBuf s buf (cSizeToInt len)

-- | An in-memory 'Backend'.
data ByteStringBackend = ByteStringBackend
  { -- | Read a 'ByteString' with the given max length.
    bsbRead :: Int -> IO ByteString,
    -- | Write a 'ByteString'.
    bsbWrite :: ByteString -> IO ()
  }
  deriving stock (Generic)

-- | This instance will silently truncate 'ByteString's which are too long.
instance Backend ByteStringBackend where
  backendRead ByteStringBackend {bsbRead} buf len = do
    bs <- bsbRead (cSizeToInt len)
    BU.unsafeUseAsCStringLen bs \(bsPtr, bsLen) -> do
      let copyLen = bsLen `min` cSizeToInt len
      copyBytes buf (castPtr bsPtr) copyLen
      pure $ intToCSize copyLen
  backendWrite ByteStringBackend {bsbWrite} buf len = do
    bsbWrite =<< B.packCStringLen (castPtr buf, cSizeToInt len)
    pure len

-- | Type-level indicator whether a 'Connection' is client- or server-side.
data Side = Client | Server

-- | A Rustls connection.
newtype Connection (side :: Side) = Connection (MVar Connection')

type role Connection nominal

data Connection' = forall b.
  Backend b =>
  Connection'
  { conn :: Ptr FFI.Connection,
    backend :: b,
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

interactTLS :: Connection' -> ReadOrWrite -> IO ()
interactTLS Connection' {..} readOrWrite = E.uninterruptibleMask \restore -> do
  putMVar ioMsgReq $ Request readOrWrite
  UsingBuffer buf len readPtr <- takeMVar ioMsgRes
  poke readPtr
    =<< restore (readOrWriteBackend buf len)
    `E.onException` done FFI.ioResultErr
  done FFI.ioResultOk
  where
    readOrWriteBackend = case readOrWrite of
      Read -> backendRead backend
      Write -> backendWrite backend
    done ioResult = do
      putMVar ioMsgReq $ Done ioResult
      DoneFFI <- takeMVar ioMsgRes
      pure ()

data RunTLSMode = TLSHandshake | TLSRead | TLSWrite
  deriving (Eq)

runTLS :: Connection' -> RunTLSMode -> IO ()
runTLS c@Connection' {..} = \case
  TLSHandshake -> loopWhileTrue do
    toBool @CBool <$> FFI.connectionIsHandshaking conn >>= \case
      True -> (||) <$> runWrite <*> runRead
      False -> pure False
  TLSRead -> do
    runTLS c TLSHandshake
    loopWhileTrue runRead
  TLSWrite -> do
    runTLS c TLSHandshake
    loopWhileTrue runWrite
  where
    runRead = do
      wantsRead <- toBool @CBool <$> FFI.connectionWantsRead conn
      when wantsRead do
        interactTLS c Read
        r <- FFI.connectionProcessNewPackets conn
        -- try to notify our peer that we encountered a TLS error
        when (r /= FFI.resultOk) $ ignoreSyncExceptions $ void runWrite
        rethrowR r
      pure wantsRead

    runWrite = do
      wantsWrite <- toBool @CBool <$> FFI.connectionWantsWrite conn
      when wantsWrite $
        interactTLS c Write
      pure wantsWrite

    loopWhileTrue action = do
      continue <- action
      when continue $ loopWhileTrue action

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
