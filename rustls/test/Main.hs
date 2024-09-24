module Main where

import Control.Concurrent.Async (concurrently)
import Control.Concurrent.STM.TMVar
import Control.Exception qualified as E
import Control.Monad (unless, when)
import Control.Monad.IO.Class
import Control.Monad.STM (atomically)
import Control.Monad.Trans.Except
import Control.Monad.Trans.State.Strict (execStateT, modify')
import Data.Acquire
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Containers.ListUtils (nubOrd)
import Data.Foldable (for_)
import Data.Functor (void)
import Data.IORef
import Data.Maybe (isJust)
import Data.Set qualified as Set
import Data.Text (Text)
import Data.Text qualified as T
import Hedgehog
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Rustls qualified
import System.Directory qualified as Dir
import System.FilePath ((</>))
import System.IO.Temp qualified as Temp
import System.Process qualified as Process
import System.Timeout
import Test.Tasty
import Test.Tasty.HUnit hiding (assert)
import Test.Tasty.Hedgehog

main :: IO ()
main =
  defaultMain . testGroup "Basic Rustls tests" $
    [ testCase "TLS versions" do
        cryptoProvider <- Rustls.getDefaultCryptoProvider
        Set.fromList [Rustls.TLS12, Rustls.TLS13]
          @?= Set.fromList (Rustls.cryptoProviderTLSVersions cryptoProvider),
      testCase "Cipher suites" do
        cryptoProvider <- Rustls.getDefaultCryptoProvider
        let cipherSuites = Rustls.cryptoProviderCipherSuites cryptoProvider
        nubOrd cipherSuites @=? cipherSuites
        let cipherSuiteIDs = Rustls.cipherSuiteID <$> cipherSuites
        nubOrd cipherSuiteIDs @=? cipherSuiteIDs
        let cipherSuiteNames = Rustls.cipherSuiteName <$> cipherSuites
        nubOrd cipherSuiteNames @=? cipherSuiteNames,
      testInMemory
    ]

testInMemory :: TestTree
testInMemory = withMiniCA \(fmap snd -> getMiniCA) ->
  testProperty "Test in-memory TLS" $ property do
    cryptoProvider <- liftIO Rustls.getDefaultCryptoProvider

    testSetup <- forAll . genTestSetup cryptoProvider =<< liftIO getMiniCA

    (res, tlsLogLines) <- runInMemoryTest testSetup

    footnote $ "TLS log:\n" <> T.unpack (T.unlines tlsLogLines)

    let TestSetup {..} = testSetup
        Rustls.ClientConfigBuilder {..} = clientConfigBuilder
        Rustls.ServerConfigBuilder {..} = serverConfigBuilder
        clientTLSVersions =
          Set.fromList $ Rustls.cryptoProviderTLSVersions clientConfigCryptoProvider
        serverTLSVersions =
          Set.fromList $ Rustls.cryptoProviderTLSVersions serverConfigCryptoProvider
        clientCipherSuites =
          Set.fromList . fmap toNegotiatedCipherSuite $
            Rustls.cryptoProviderCipherSuites clientConfigCryptoProvider
        serverCipherSuites =
          Set.fromList . fmap toNegotiatedCipherSuite $
            Rustls.cryptoProviderCipherSuites serverConfigCryptoProvider
    case res of
      Right TestOutcome {..} -> do
        label "Success"
        clientSends === serverReceived
        clientSends === clientReceived
        if clientConfigEnableSNI
          then sniHostname === Just testHostname
          else sniHostname === Nothing
        assert $
          Set.fromList [clientTLSVersion, serverTLSVersion]
            `Set.isSubsetOf` Set.fromList [Rustls.TLS12, Rustls.TLS13]
        negotiatedClientALPNProtocol === negotiatedServerALPNProtocol
        assert $
          maybe Set.empty Set.singleton negotiatedClientALPNProtocol
            `Set.isSubsetOf` ( Set.fromList clientConfigALPNProtocols
                                 `Set.intersection` Set.fromList serverConfigALPNProtocols
                             )
        clientCipherSuite === serverCipherSuite
        assert $
          clientCipherSuite
            `Set.member` (clientCipherSuites `Set.intersection` serverCipherSuites)
        assert $ isJust clientPeerCert
        case Rustls.clientCertVerifierPolicy <$> serverConfigClientCertVerifier of
          Nothing ->
            serverPeerCert === Nothing
          Just Rustls.AllowAnyAuthenticatedClient ->
            assert $ isJust serverPeerCert
          Just Rustls.AllowAnyAnonymousOrAuthenticatedClient ->
            isJust serverPeerCert /== null clientConfigCertifiedKeys
      Left (ex :: Rustls.RustlsException) -> do
        annotate $ E.displayException ex
        if
          | Set.fromList clientConfigALPNProtocols
              `Set.disjoint` Set.fromList serverConfigALPNProtocols -> do
              label "Expected TLS failure: No common ALPN protocol"
              success
          | clientTLSVersions `Set.disjoint` serverTLSVersions -> do
              label "Expected TLS failure: No common TLS version"
              success
          | Just Rustls.AllowAnyAuthenticatedClient <-
              Rustls.clientCertVerifierPolicy <$> serverConfigClientCertVerifier,
            null clientConfigCertifiedKeys -> do
              label "Expected TLS failure: No client cert"
              success
          | Rustls.PlatformServerCertVerifier <- clientConfigServerCertVerifier -> do
              label "Expected TLS failure: Platform verifier denies self-signed cert"
              success
          | otherwise -> failure

testHostname :: Text
testHostname = "example.org"

testMessageLen :: Int
testMessageLen = 1000

data TestSetup = TestSetup
  { clientConfigBuilder :: Rustls.ClientConfigBuilder,
    serverConfigBuilder :: Rustls.ServerConfigBuilder,
    clientSends :: [ByteString]
  }
  deriving stock (Show)

data MiniCA = MiniCA
  { miniCAFile :: FilePath,
    miniCACert :: ByteString,
    miniCAClientCertKey, miniCAServerCertKey :: Rustls.CertifiedKey
  }

genTestSetup :: (MonadGen m) => Rustls.CryptoProvider -> MiniCA -> m TestSetup
genTestSetup cryptoProvider MiniCA {..} = do
  commonALPNProtocols <- genALPNProtocols
  clientConfigCryptoProvider <- genCryptoProvider
  clientConfigServerCertVerifier <- do
    Gen.frequency
      [ (1, pure Rustls.PlatformServerCertVerifier),
        (10,) do
          parsing <- Gen.enumBounded
          serverCertVerifierCertificates <-
            pure
              <$> Gen.element
                [ Rustls.PEMCertificatesInMemory miniCACert parsing,
                  Rustls.PemCertificatesFromFile miniCAFile parsing
                ]
          let serverCertVerifierCRLs = [] -- TODO test this
          pure Rustls.ServerCertVerifier {..}
      ]
  clientConfigALPNProtocols <- (commonALPNProtocols <>) <$> genALPNProtocols
  clientConfigEnableSNI <- Gen.bool_
  clientConfigCertifiedKeys <- Gen.subsequence [miniCAClientCertKey]
  let clientConfigBuilder = Rustls.ClientConfigBuilder {..}
  serverConfigCryptoProvider <- genCryptoProvider
  serverConfigALPNProtocols <- (commonALPNProtocols <>) <$> genALPNProtocols
  serverConfigIgnoreClientOrder <- Gen.bool_
  serverConfigClientCertVerifier <- Gen.maybe do
    clientCertVerifierPolicy <- Gen.enumBounded
    let clientCertVerifierCertificates =
          pure $
            Rustls.PEMCertificatesInMemory
              miniCACert
              Rustls.PEMCertificateParsingStrict
        clientCertVerifierCRLs = [] -- TODO test this
    pure Rustls.ClientCertVerifier {..}
  let serverConfigCertifiedKeys = pure miniCAServerCertKey
      serverConfigBuilder = Rustls.ServerConfigBuilder {..}
  clientSends <-
    -- TODO using 0 as a lower bound should work, but causes timeouts for some
    -- reason
    Gen.list (Range.linear 1 10) $
      Gen.filterT (/= "close") $
        Gen.bytes (Range.linear 1 50)
  pure TestSetup {..}
  where
    genALPNProtocols =
      Gen.list (Range.constant 0 10) $
        Rustls.ALPNProtocol <$> Gen.bytes (Range.constant 1 10)

    genCryptoProvider =
      Gen.frequency
        [ (1, pure cryptoProvider),
          (10,) do
            tlsVersions <- Gen.shuffle =<< Gen.subsequence allTLSVersions
            let cipherSuites =
                  [ cipherSuite
                  | cipherSuite <- allCipherSuites,
                    Rustls.cipherSuiteTLSVersion cipherSuite `elem` tlsVersions
                  ]
            pure case Rustls.setCryptoProviderCipherSuites cipherSuites cryptoProvider of
              Left e -> error $ "unexpected: " <> show e
              Right cp -> cp
        ]
      where
        allTLSVersions = Rustls.cryptoProviderTLSVersions cryptoProvider
        allCipherSuites = Rustls.cryptoProviderCipherSuites cryptoProvider

data TestOutcome = TestOutcome
  { negotiatedClientALPNProtocol,
    negotiatedServerALPNProtocol ::
      Maybe Rustls.ALPNProtocol,
    clientTLSVersion, serverTLSVersion :: Rustls.TLSVersion,
    clientCipherSuite, serverCipherSuite :: Rustls.NegotiatedCipherSuite,
    sniHostname :: Maybe Text,
    clientPeerCert, serverPeerCert :: Maybe Rustls.DERCertificate,
    clientReceived, serverReceived :: [ByteString]
  }

runInMemoryTest ::
  (MonadIO m) =>
  TestSetup ->
  m (Either Rustls.RustlsException TestOutcome, [Text])
runInMemoryTest TestSetup {..} = do
  logRef <- liftIO $ newIORef []

  let runServer backend = withAcquire
        do
          lc <- mkTestLogCallback logRef "SERVER"
          rustlsConfig <-
            (\cfg -> cfg {Rustls.serverConfigLogCallback = Just lc})
              <$> Rustls.buildServerConfig serverConfigBuilder
          Rustls.newServerConnection backend rustlsConfig
        \conn -> do
          (alpnProtocol, tlsVersion, cipherSuite, sniHostname, peerCert) <-
            Rustls.handshake conn $
              (,,,,)
                <$> Rustls.getALPNProtocol
                <*> Rustls.getTLSVersion
                <*> Rustls.getNegotiatedCipherSuite
                <*> Rustls.getSNIHostname
                <*> Rustls.getPeerCertificate 0
          received <-
            let go = do
                  bs <- Rustls.readBS conn testMessageLen
                  when (bs /= "close") do
                    modify' (bs :)
                    Rustls.writeBS conn bs
                    go
             in recordOutput go
          pure (alpnProtocol, tlsVersion, cipherSuite, sniHostname, peerCert, received)

      runClient backend = withAcquire
        do
          lc <- mkTestLogCallback logRef "CLIENT"
          rustlsConfig <-
            (\cfg -> cfg {Rustls.clientConfigLogCallback = Just lc})
              <$> Rustls.buildClientConfig clientConfigBuilder
          Rustls.newClientConnection backend rustlsConfig testHostname
        \conn -> do
          (alpnProtocol, tlsVersion, cipherSuite, peerCert) <-
            Rustls.handshake conn $
              (,,,)
                <$> Rustls.getALPNProtocol
                <*> Rustls.getTLSVersion
                <*> Rustls.getNegotiatedCipherSuite
                <*> Rustls.getPeerCertificate 0
          received <- recordOutput . for_ clientSends $ \bs -> do
            Rustls.writeBS conn bs
            bs <- Rustls.readBS conn testMessageLen
            modify' (bs :)
          Rustls.writeBS conn "close"
          pure (alpnProtocol, tlsVersion, cipherSuite, peerCert, received)

  (backend0, backend1) <- mkConnectedBackends

  res <- liftIO . runExceptT $ do
    ( ( negotiatedServerALPNProtocol,
        serverTLSVersion,
        serverCipherSuite,
        sniHostname,
        serverPeerCert,
        serverReceived
        ),
      ( negotiatedClientALPNProtocol,
        clientTLSVersion,
        clientCipherSuite,
        clientPeerCert,
        clientReceived
        )
      ) <-
      ExceptT . E.try . timeout' $
        concurrently (runServer backend0) (runClient backend1)
    pure TestOutcome {..}
  tlsLogLines <- liftIO $ reverse <$> readIORef logRef
  pure (res, tlsLogLines)
  where
    recordOutput = fmap reverse . flip execStateT []

    timeout' action =
      timeout (10 ^ (6 :: Int)) action >>= \case
        Just a -> pure a
        Nothing -> fail "timeout!"

withMiniCA :: (IO (FilePath, MiniCA) -> TestTree) -> TestTree
withMiniCA = withResource
  do
    tmpDir <-
      flip Temp.createTempDirectory "hs-rustls-minica"
        =<< Temp.getCanonicalTemporaryDirectory
    for_ ["example.org", "client.example.org"] \domain -> do
      let cp = Process.proc "minica" ["-domains", domain]
      void $ Process.readCreateProcess (cp {Process.cwd = Just tmpDir}) ""
    let miniCAFile = tmpDir </> "minica.pem"
    miniCACert <- B.readFile miniCAFile
    let miniCACertKey domain = do
          privateKey <- B.readFile $ tmpDir </> domain </> "key.pem"
          certificateChain <- B.readFile $ tmpDir </> domain </> "cert.pem"
          pure Rustls.CertifiedKey {..}
    miniCAClientCertKey <- miniCACertKey "client.example.org"
    miniCAServerCertKey <- miniCACertKey "example.org"
    pure (tmpDir, MiniCA {..})
  \(tmpDir, _) -> Dir.removeDirectoryRecursive tmpDir

mkConnectedBackends :: (MonadIO m) => m (Rustls.Backend, Rustls.Backend)
mkConnectedBackends = liftIO do
  buf0 <- newEmptyTMVarIO
  buf1 <- newEmptyTMVarIO
  pure (mkBSBackend buf0 buf1, mkBSBackend buf1 buf0)
  where
    mkBSBackend readBuf writeBuf = Rustls.mkByteStringBackend bsbRead bsbWrite
      where
        bsbRead len = atomically do
          (bs, bs') <- B.splitAt len <$> takeTMVar readBuf
          unless (B.null bs') $ putTMVar readBuf bs'
          pure bs
        bsbWrite bs =
          atomically $ putTMVar writeBuf bs

mkTestLogCallback :: IORef [Text] -> Text -> Acquire Rustls.LogCallback
mkTestLogCallback ref id = Rustls.newLogCallback \lvl msg -> do
  let lvlTxt = case lvl of
        Rustls.LogLevelError -> "ERROR"
        Rustls.LogLevelWarn -> "WARN"
        Rustls.LogLevelInfo -> "INFO"
        Rustls.LogLevelDebug -> "DEBUG"
        Rustls.LogLevelTrace -> "TRACE"
      line = "[" <> id <> "] [" <> lvlTxt <> "] " <> msg
  atomicModifyIORef' ref ((,()) . (line :))

toNegotiatedCipherSuite :: Rustls.CipherSuite -> Rustls.NegotiatedCipherSuite
toNegotiatedCipherSuite Rustls.CipherSuite {..} =
  Rustls.NegotiatedCipherSuite
    { negotiatedCipherSuiteID = cipherSuiteID,
      negotiatedCipherSuiteName = cipherSuiteName
    }
