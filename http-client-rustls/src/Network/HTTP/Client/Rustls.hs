-- | Make HTTPS connections using
-- [http-client](https://hackage.haskell.org/package/http-client) and
-- [Rustls](https://github.com/rustls/rustls).
--
-- >>> import qualified Rustls
-- >>> import qualified Network.HTTP.Client as HTTP
-- >>> :{
-- newRustlsManager :: IO HTTP.Manager
-- newRustlsManager = do
--   clientConfig <-
--     Rustls.buildClientConfig $
--       Rustls.defaultClientConfigBuilder serverCertVerifier
--   HTTP.newManager $ rustlsManagerSettings clientConfig
--   where
--     -- For now, rustls-ffi does not provide a built-in way to access
--     -- the OS certificate store.
--     serverCertVerifier =
--       Rustls.ServerCertVerifier
--         { Rustls.serverCertVerifierCertificates =
--             pure $
--               Rustls.PemCertificatesFromFile
--                 "/etc/ssl/certs/ca-certificates.crt"
--                 Rustls.PEMCertificateParsingStrict,
--           Rustls.serverCertVerifierCRLs = []
--         }
-- >>> :}
--
-- >>> :{
-- example = do
--   mgr <- newRustlsManager -- this should be shared across multiple requests
--   req <- HTTP.parseUrlThrow "https://example.org"
--   res <- HTTP.httpLbs req mgr
--   print $ HTTP.responseBody res
-- :}
module Network.HTTP.Client.Rustls
  ( rustlsManagerSettings,
  )
where

import Control.Exception qualified as E
import Data.Acquire (ReleaseType (..))
import Data.Acquire.Internal (Acquire (..), Allocated (..))
import Data.ByteString.Builder.Extra qualified as B
import Data.Text qualified as T
import Network.HTTP.Client qualified as HTTP
import Network.HTTP.Client.Internal qualified as HTTP
import Network.Socket qualified as NS
import Rustls qualified

-- | Get TLS-enabled HTTP 'HTTP.ManagerSettings' from a Rustls
-- 'Rustls.ClientConfig', consumable via 'HTTP.newManager'.
rustlsManagerSettings :: Rustls.ClientConfig -> HTTP.ManagerSettings
rustlsManagerSettings conf =
  HTTP.defaultManagerSettings
    { HTTP.managerTlsConnection = pure \hostAddress host port ->
        HTTP.withSocket mempty hostAddress host port \sock ->
          makeTlsConnection conf sock host,
      HTTP.managerTlsProxyConnection = pure \connStr checkConn serverName _ host port ->
        HTTP.withSocket mempty Nothing host port \sock -> do
          conn <- HTTP.socketConnection sock B.defaultChunkSize
          HTTP.connectionWrite conn connStr
          checkConn conn
          makeTlsConnection conf sock serverName,
      HTTP.managerWrapException = \req ->
        E.handle @Rustls.RustlsException
          (E.throwIO . HTTP.HttpExceptionRequest req . HTTP.InternalException . E.toException)
          . HTTP.managerWrapException HTTP.defaultManagerSettings req
    }
  where
    makeTlsConnection conf socket hostname = E.mask \restore -> do
      let strippedHost = T.pack $ HTTP.strippedHostName hostname
          backend = Rustls.mkSocketBackend socket
          Acquire allocate = Rustls.newClientConnection backend conf strippedHost
      Allocated conn freeConn <- allocate restore
      HTTP.makeConnection
        do Rustls.readBS conn (fromIntegral B.defaultChunkSize)
        do Rustls.writeBS conn
        do freeConn ReleaseNormal; NS.close socket
