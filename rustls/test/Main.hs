module Main where

import Control.Applicative (liftA2)
import Control.Concurrent.Async (concurrently)
import Control.Concurrent.STM.TMVar
import qualified Control.Exception as E
import Control.Monad (join, unless, when)
import Control.Monad.IO.Class
import Control.Monad.STM (atomically)
import Control.Monad.Trans.Except
import Control.Monad.Trans.State.Strict (execStateT, modify')
import Data.Acquire
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Foldable (for_)
import Data.Functor (void)
import Data.IORef
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Set as S
import Data.Text (Text)
import qualified Data.Text as T
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import qualified Rustls
import qualified System.Directory as Dir
import System.FilePath ((</>))
import qualified System.IO.Temp as Temp
import qualified System.Process as Process
import Test.Tasty
import Test.Tasty.HUnit hiding (assert)
import Test.Tasty.Hedgehog

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

genTestSetup :: MonadGen m => MiniCA -> m TestSetup
genTestSetup MiniCA {..} = do
  commonALPNProtocols <- genALPNProtocols
  clientConfigRoots <-
    Gen.element
      [ Rustls.ClientRootsFromFile miniCAFile,
        Rustls.ClientRootsInMemory [Rustls.PEMCertificatesStrict miniCACert],
        Rustls.ClientRootsInMemory [Rustls.PEMCertificatesLax miniCACert]
      ]
  clientConfigALPNProtocols <- (commonALPNProtocols <>) <$> genALPNProtocols
  clientConfigEnableSNI <- Gen.bool_
  clientConfigTLSVersions <- genTLSVersions
  clientConfigCertifiedKeys <- Gen.subsequence [miniCAClientCertKey]
  let clientConfigCipherSuites = getCipherSuites clientConfigTLSVersions
      clientConfigBuilder = Rustls.ClientConfigBuilder {..}
  serverConfigALPNProtocols <- (commonALPNProtocols <>) <$> genALPNProtocols
  serverConfigIgnoreClientOrder <- Gen.bool_
  serverConfigTLSVersions <- genTLSVersions
  serverConfigClientCertVerifier <-
    Gen.element
      [ Nothing,
        Just $ Rustls.ClientCertVerifier [Rustls.PEMCertificatesStrict miniCACert],
        Just $ Rustls.ClientCertVerifierOptional [Rustls.PEMCertificatesStrict miniCACert]
      ]
  let serverConfigCipherSuites = getCipherSuites serverConfigTLSVersions
      serverConfigCertifiedKeys = pure miniCAServerCertKey
      serverConfigBuilder = Rustls.ServerConfigBuilder {..}
  clientSends <-
    Gen.list (Range.linear 0 10) $
      Gen.filterT (/= "close") $
        Gen.bytes (Range.linear 1 50)
  pure TestSetup {..}
  where
    genALPNProtocols =
      Gen.list (Range.constant 0 10) $
        Rustls.ALPNProtocol <$> Gen.bytes (Range.constant 1 10)
    genTLSVersions =
      Gen.shuffle =<< Gen.subsequence (NE.toList Rustls.allTLSVersions)
    getCipherSuites tlsVersions =
      filter ((`elem` tlsVersions) . tlsVersionFromCipherSuite) $
        NE.toList Rustls.allCipherSuites

data TestOutcome = TestOutcome
  { negotiatedClientALPNProtocol, negotiatedServerALPNProtocol :: Maybe Rustls.ALPNProtocol,
    clientTLSVersion, serverTLSVersion :: Rustls.TLSVersion,
    clientCipherSuite, serverCipherSuite :: Rustls.CipherSuite,
    sniHostname :: Maybe Text,
    clientPeerCert, serverPeerCert :: Maybe Rustls.DERCertificate,
    clientReceived, serverReceived :: [ByteString]
  }

main :: IO ()
main =
  defaultMain . testGroup "Basic Rustls tests" $
    [ testCase "Test version" $ Rustls.version @?= "rustls-ffi/0.9.1/rustls/0.20.4",
      testCase "TLS versions" do
        S.fromList [Rustls.TLS12, Rustls.TLS13]
          @?= S.fromList (NE.toList Rustls.defaultTLSVersions)
        assertBool "Unexpected default TLS versions" $
          S.fromList (NE.toList Rustls.defaultTLSVersions)
            `S.isSubsetOf` S.fromList (NE.toList Rustls.allTLSVersions),
      testCase "Cipher suites" do
        let defaultCipherSuites = S.fromList (NE.toList Rustls.defaultCipherSuites)
            allCipherSuites = S.fromList (NE.toList Rustls.allCipherSuites)
        assertBool "Unexpected default cipher suites" $
          defaultCipherSuites `S.isSubsetOf` allCipherSuites
        assertBool "Misbehaving ID function for cipher suites" $
          S.map Rustls.cipherSuiteID defaultCipherSuites
            `S.isSubsetOf` S.map Rustls.cipherSuiteID allCipherSuites
        assertBool "Misbehaving display function for cipher suites" $
          S.map Rustls.showCipherSuite defaultCipherSuites
            `S.isSubsetOf` S.map Rustls.showCipherSuite allCipherSuites,
      testInMemory
    ]
  where
    testHostname = "example.org"
    testMessageLen = 1000
    testInMemory = withMiniCA \(fmap snd -> getMiniCA) ->
      testPropertyNamed "Test in-memory TLS" "Test in-memory TLS" $ property do
        TestSetup {..} <- forAll . genTestSetup =<< liftIO getMiniCA

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
                      <*> Rustls.getCipherSuite
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
                      <*> Rustls.getCipherSuite
                      <*> Rustls.getPeerCertificate 0
                received <- recordOutput . for_ clientSends $ \bs -> do
                  Rustls.writeBS conn bs
                  bs <- Rustls.readBS conn testMessageLen
                  modify' (bs :)
                Rustls.writeBS conn "close"
                pure (alpnProtocol, tlsVersion, cipherSuite, peerCert, received)

        (backend0, backend1) <- mkConnectedBSBackends

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
            ExceptT . E.try $ concurrently (runServer backend0) (runClient backend1)
          pure TestOutcome {..}

        do
          logLines <- liftIO $ T.unlines . reverse <$> readIORef logRef
          footnote $ "TLS log:\n" <> T.unpack logLines

        let Rustls.ClientConfigBuilder {..} = clientConfigBuilder
            Rustls.ServerConfigBuilder {..} = serverConfigBuilder
            clientTLSVersions =
              nonEmptySet Rustls.defaultTLSVersions clientConfigTLSVersions
            serverTLSVersions =
              nonEmptySet Rustls.defaultTLSVersions serverConfigTLSVersions
            clientCipherSuites =
              nonEmptySet Rustls.defaultCipherSuites clientConfigCipherSuites
            serverCipherSuites =
              nonEmptySet Rustls.defaultCipherSuites serverConfigCipherSuites
        case res of
          Right TestOutcome {..} -> do
            label "Success"
            clientSends === serverReceived
            clientSends === clientReceived
            if clientConfigEnableSNI
              then sniHostname === Just testHostname
              else sniHostname === Nothing
            assert $
              S.fromList [clientTLSVersion, serverTLSVersion]
                `S.isSubsetOf` S.fromList [Rustls.TLS12, Rustls.TLS13]
            negotiatedClientALPNProtocol === negotiatedServerALPNProtocol
            assert $
              maybe S.empty S.singleton negotiatedClientALPNProtocol
                `S.isSubsetOf` ( S.fromList clientConfigALPNProtocols
                                   `S.intersection` S.fromList serverConfigALPNProtocols
                               )
            clientCipherSuite === serverCipherSuite
            assert $
              clientCipherSuite
                `S.member` (clientCipherSuites `S.intersection` serverCipherSuites)
            assert $ isJust clientPeerCert
            case serverConfigClientCertVerifier of
              Nothing ->
                serverPeerCert === Nothing
              Just (Rustls.ClientCertVerifier _) ->
                assert $ isJust serverPeerCert
              Just (Rustls.ClientCertVerifierOptional _) ->
                isJust serverPeerCert /== null clientConfigCertifiedKeys
          Left (ex :: Rustls.RustlsException) -> do
            label "Expected TLS failure"
            annotate $ E.displayException ex
            if
                | S.fromList clientConfigALPNProtocols
                    `S.disjoint` S.fromList serverConfigALPNProtocols ->
                    success
                | clientTLSVersions `S.disjoint` serverTLSVersions ->
                    success
                | Just (Rustls.ClientCertVerifier _) <- serverConfigClientCertVerifier,
                  null clientConfigCertifiedKeys ->
                    success
                | otherwise -> failure
      where
        recordOutput = fmap reverse . flip execStateT []

        nonEmptySet def = S.fromList . NE.toList . fromMaybe def . NE.nonEmpty

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
          do \(tmpDir, _) -> Dir.removeDirectoryRecursive tmpDir

mkConnectedBSBackends :: MonadIO m => m (Rustls.ByteStringBackend, Rustls.ByteStringBackend)
mkConnectedBSBackends = liftIO do
  (buf0, buf1) <- join (liftA2 (,)) newEmptyTMVarIO
  pure (mkBSBackend buf0 buf1, mkBSBackend buf1 buf0)
  where
    mkBSBackend readBuf writeBuf = Rustls.ByteStringBackend {..}
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

tlsVersionFromCipherSuite :: Rustls.CipherSuite -> Rustls.TLSVersion
tlsVersionFromCipherSuite cipherSuite
  | "TLS_" `T.isPrefixOf` str = Rustls.TLS12
  | "TLS13_" `T.isPrefixOf` str = Rustls.TLS13
  | otherwise = error "unexpected cipher suite"
  where
    str = Rustls.showCipherSuite cipherSuite
