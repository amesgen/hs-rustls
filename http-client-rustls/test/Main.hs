module Main where

import Control.Exception qualified as E
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Network.HTTP.Client qualified as HTTP
import Network.HTTP.Client.Internal as HTTP (hostAddress)
import Network.HTTP.Client.Rustls
import Network.HTTP.Types qualified as HTTP
import Network.Socket (tupleToHostAddress)
import Network.Socket.Wait (wait)
import Rustls qualified
import System.Directory qualified as Dir
import System.FilePath ((</>))
import System.IO.Temp qualified as Temp
import System.Process qualified as Process
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $ withRustlsManagerAndServer \(fmap fst -> mgr) ->
  testGroup
    "HTTPS-via-Rustls connectivity tests"
    [ testCase "Make an HTTPS request" do
        req <- modifyReq <$> HTTP.parseUrlThrow "https://example.org"
        res <- HTTP.httpNoBody req =<< mgr
        HTTP.responseStatus res @?= HTTP.status200,
      testCase "Download byte stream" do
        req <- modifyReq <$> HTTP.parseUrlThrow "https://example.org/file"
        res <- HTTP.httpLbs req =<< mgr
        BL.length (HTTP.responseBody res) @?= fromIntegral fileLength,
      testCase "Fail on wrong host" $
        failsOn mgr "https://examplee.org"
    ]
  where
    fileLength = 100000
    fileByte = 42

    modifyReq req =
      req
        { HTTP.port = 8080,
          HTTP.hostAddress = Just $ tupleToHostAddress (127, 0, 0, 1)
        }

    failsOn mgr req =
      E.try (HTTP.httpNoBody (modifyReq req) =<< mgr) >>= \case
        Right _ ->
          assertFailure "Established invalid TLS connection!"
        Left (E.fromException -> Just (HTTP.HttpExceptionRequest _ (HTTP.InternalException ie)))
          | Just (e :: Rustls.RustlsException) <- E.fromException ie,
            Rustls.isCertError e ->
              mempty
        Left (E.SomeException e) ->
          assertFailure $ "Failed with unexpected exception: " <> show e

    withRustlsManagerAndServer = withResource prepareServer cleanupServer
      where
        prepareServer = do
          tmpDir <-
            flip Temp.createTempDirectory "hs-rustls-server"
              =<< Temp.getCanonicalTemporaryDirectory

          let cp = Process.proc "minica" ["-domains", "example.org"]
          _ <- Process.readCreateProcess (cp {Process.cwd = Just tmpDir}) ""
          builder <- Rustls.defaultClientConfigBuilder
          mgr <-
            HTTP.newManager . rustlsManagerSettings
              =<< Rustls.buildClientConfig
                builder
                  { Rustls.clientConfigServerCertVerifier =
                      Rustls.ServerCertVerifier
                        { Rustls.serverCertVerifierCertificates =
                            pure $
                              Rustls.PemCertificatesFromFile
                                (tmpDir </> "minica.pem")
                                Rustls.PEMCertificateParsingStrict,
                          Rustls.serverCertVerifierCRLs = [],
                          Rustls.serverCertVerifierEnforceCRLExpiry = True
                        }
                  }
          B.writeFile (tmpDir </> "file") $ B.replicate fileLength fileByte
          procInfo <-
            Process.createProcess $
              ( Process.proc
                  "miniserve"
                  [ "--tls-cert",
                    tmpDir </> "example.org/cert.pem",
                    "--tls-key",
                    tmpDir </> "example.org/key.pem",
                    tmpDir
                  ]
              )
                { Process.std_out = Process.CreatePipe,
                  Process.std_in = Process.CreatePipe
                }
          wait "127.0.0.1" 8080
          pure (mgr, (tmpDir, procInfo))
        cleanupServer (_, (tmpDir, procInfo)) = E.mask_ do
          Process.cleanupProcess procInfo
          Dir.removeDirectoryRecursive tmpDir
