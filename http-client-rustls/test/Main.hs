module Main where

import qualified Control.Exception as E
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Client.Internal as HTTP (hostAddress)
import Network.HTTP.Client.Rustls
import qualified Network.HTTP.Types as HTTP
import Network.Socket (tupleToHostAddress)
import Network.Socket.Wait (wait)
import qualified Rustls
import qualified System.Directory as Dir
import System.FilePath ((</>))
import qualified System.IO.Temp as Temp
import qualified System.Process as Process
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $ withRustlsManagerAndServer \(fmap fst -> mgr) ->
  let failsOn req =
        E.try (HTTP.httpNoBody (modifyReq req) =<< mgr) >>= \case
          Right _ ->
            assertFailure "Established invalid TLS connection!"
          Left (E.fromException -> Just (HTTP.HttpExceptionRequest _ (HTTP.InternalException ie)))
            | Just (e :: Rustls.RustlsException) <- E.fromException ie,
              Rustls.isCertError e ->
                mempty
          Left (E.SomeException e) ->
            assertFailure $ "Failed with unexpected exception: " <> show e
   in testGroup
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
            failsOn "https://examplee.org"
        ]
  where
    fileLength = 100000
    fileByte = 42

    modifyReq req =
      req
        { HTTP.port = 8080,
          HTTP.hostAddress = Just $ tupleToHostAddress (127, 0, 0, 1)
        }

    withRustlsManagerAndServer = withResource prepareServer cleanupServer
      where
        prepareServer = do
          tmpDir <-
            flip Temp.createTempDirectory "hs-rustls-server"
              =<< Temp.getCanonicalTemporaryDirectory

          let cp = Process.proc "minica" ["-domains", "example.org"]
          _ <- Process.readCreateProcess (cp {Process.cwd = Just tmpDir}) ""
          mgr <-
            HTTP.newManager . rustlsManagerSettings
              =<< Rustls.buildClientConfig
                ( Rustls.defaultClientConfigBuilder
                    (Rustls.ClientRootsFromFile $ tmpDir </> "minica.pem")
                )
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
