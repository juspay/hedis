{-# LANGUAGE TupleSections #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE DeriveGeneric #-}
module Database.Redis.Connection where

import Control.Exception as CE
import qualified Control.Monad.Catch as Catch
import Control.Monad.IO.Class(liftIO, MonadIO)
import Control.Monad(when,foldM, forever)

-- import Control.Concurrent.MVar(modifyMVar)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as Char8
import Data.Functor(void)
import qualified Data.IntMap.Strict as IntMap
import Data.Pool(Pool, withResource, createPool, destroyAllResources)
import Data.Typeable
import Data.List (nub)
import qualified Data.Time as Time
import Network.TLS (ClientParams)
import qualified Network.Socket as NS
import qualified Data.HashMap.Strict as HM
import System.Random (randomRIO)
import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)
import Text.Read (readMaybe)

import qualified Database.Redis.ProtocolPipelining as PP
import Database.Redis.Core(Redis, runRedisInternal, runRedisClusteredInternal)
import Database.Redis.Protocol(Reply(..))
import Database.Redis.Cluster(ShardMap(..), Node(..), Shard(..))
import qualified Database.Redis.Cluster as Cluster
import qualified Database.Redis.ConnectionContext as CC
import qualified System.Timeout as T
import Network.HTTP.Client
-- import Network.HTTP.Types.Status (statusCode)
import Network.HTTP.Client.TLS
import Data.Aeson as A hiding (Error)
import Data.Text as T (replace, pack, Text)
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
-- import qualified Data.ByteString.Lazy.Char8 as BL
import Network.HTTP.Types.Header
import qualified Web.JWT as JWT
-- import Control.Exception (Exception, throwIO)
import qualified Crypto.PubKey.RSA.Types as RSAT
import qualified Data.Time as DT
import qualified Data.Time.Clock.POSIX as DT
import qualified Data.Map.Strict as DMS
import Data.IORef
import Control.Concurrent
import GHC.Generics
import Control.Applicative
import Database.Redis.Commands
    ( ping
    , select
    , auth
    , clusterSlots
    , command
    , readOnly
    , ClusterSlotsResponse(..)
    , ClusterSlotsResponseEntry(..)
    , ClusterSlotsNode(..))

--------------------------------------------------------------------------------
-- Connection
--

-- |A threadsafe pool of network connections to a Redis server. Use the
--  'connect' function to create one.
data Connection
    = NonClusteredConnection (Pool PP.Connection)
    | ClusteredConnection ConnectInfo Cluster.Connection

-- |Information for connnecting to a Redis server.
--
-- It is recommended to not use the 'ConnInfo' data constructor directly.
-- Instead use 'defaultConnectInfo' and update it with record syntax. For
-- example to connect to a password protected Redis server running on localhost
-- and listening to the default port:
--
-- @
-- myConnectInfo :: ConnectInfo
-- myConnectInfo = defaultConnectInfo {connectAuth = Just \"secret\"}
-- @
--
data ConnectInfo = ConnInfo
    { connectHost           :: NS.HostName
    , connectPort           :: CC.PortID
    , connectAuth           :: Maybe B.ByteString
    , connectReadOnly       :: Bool
    -- ^ When the server is protected by a password, set 'connectAuth' to 'Just'
    --   the password. Each connection will then authenticate by the 'auth'
    --   command.
    , connectDatabase       :: Integer
    -- ^ Each connection will 'select' the database with the given index.
    , connectMaxConnections :: Int
    -- ^ Maximum number of connections to keep open. The smallest acceptable
    --   value is 1.
    , connectMaxIdleTime    :: Time.NominalDiffTime
    -- ^ Amount of time for which an unused connection is kept open. The
    --   smallest acceptable value is 0.5 seconds. If the @timeout@ value in
    --   your redis.conf file is non-zero, it should be larger than
    --   'connectMaxIdleTime'.
    , connectTimeout        :: Maybe Time.NominalDiffTime
    -- ^ Optional timeout until connection to Redis gets
    --   established. 'ConnectTimeoutException' gets thrown if no socket
    --   get connected in this interval of time.
    , connectTLSParams      :: Maybe ClientParams
    -- ^ Optional TLS parameters. TLS will be enabled if this is provided.
    , isDynamicAuthRequired :: Maybe Bool
    , maybeAuthTokenRef     :: Maybe ShowableIORefText
    } deriving Show

data ConnectError = ConnectAuthError Reply
                  | ConnectSelectError Reply
    deriving (Eq, Show, Typeable)

instance Exception ConnectError

newtype ShowableIORefText = ShowableIORefText (IORef Text)

instance Show ShowableIORefText where
    show _ = "io ref text" :: String

-- |Default information for connecting:
--
-- @
--  connectHost           = \"localhost\"
--  connectPort           = PortNumber 6379 -- Redis default port
--  connectAuth           = Nothing         -- No password
--  connectDatabase       = 0               -- SELECT database 0
--  connectMaxConnections = 50              -- Up to 50 connections
--  connectMaxIdleTime    = 30              -- Keep open for 30 seconds
--  connectTimeout        = Nothing         -- Don't add timeout logic
--  connectTLSParams      = Nothing         -- Do not use TLS
-- @
--
defaultConnectInfo :: ConnectInfo
defaultConnectInfo = ConnInfo
    { connectHost           = "localhost"
    , connectPort           = CC.PortNumber 6379
    , connectAuth           = Nothing
    , connectReadOnly       = False
    , connectDatabase       = 0
    , connectMaxConnections = 50
    , connectMaxIdleTime    = 30
    , connectTimeout        = Nothing
    , connectTLSParams      = Nothing
    , isDynamicAuthRequired = Nothing
    , maybeAuthTokenRef     = Nothing
    }

defaultClusterConnectInfo :: ConnectInfo
defaultClusterConnectInfo = ConnInfo
    { connectHost           = "localhost"
    , connectPort           = CC.PortNumber 30001
    , connectAuth           = Nothing
    , connectReadOnly       = False
    , connectDatabase       = 0
    , connectMaxConnections = 50
    , connectMaxIdleTime    = 30
    , connectTimeout        = Nothing
    , connectTLSParams      = Nothing
    , isDynamicAuthRequired = Nothing
    , maybeAuthTokenRef     = Nothing
    }

createConnection :: ConnectInfo -> IO PP.Connection
createConnection ConnInfo{..} = do
    let timeoutOptUs =
          round . (1000000 *) <$> connectTimeout
    conn <- PP.connect connectHost connectPort timeoutOptUs
    conn' <- case connectTLSParams of
               Nothing -> return conn
               Just tlsParams -> PP.enableTLS tlsParams conn
    PP.beginReceiving conn'
    -- putStrLn $ ("Making new connection with port" ) <> show connectPort
    connectAuth' <- 
        case maybeAuthTokenRef of
            Just (ShowableIORefText authTokenRef) -> do
                authToken <- readIORef authTokenRef
                return $ Just $ T.encodeUtf8 authToken
            _ -> return connectAuth
    putStrLn $ "createConnection: redis pass is" <> show connectAuth'

    runRedisInternal conn' $ do
        -- AUTH
        case connectAuth' of
            Nothing   -> return ()
            Just pass -> do
              resp <- auth pass
              case resp of
                Left r -> liftIO $ throwIO $ ConnectAuthError r
                _      -> return ()
        -- SELECT
        when (connectDatabase /= 0) $ do
          resp <- select connectDatabase
          case resp of
              Left r -> liftIO $ throwIO $ ConnectSelectError r
              _      -> return ()
    return conn'

-- |Constructs a 'Connection' pool to a Redis server designated by the
--  given 'ConnectInfo'. The first connection is not actually established
--  until the first call to the server.
connect :: ConnectInfo -> IO Connection
connect cInfo@ConnInfo{..} = do
    putStrLn "NonClusteredConnection"
    -- putStrLn $ show cInfo
    newConnInfo <-
        case isDynamicAuthRequired of
            Just True -> do
                manager <- newManager tlsManagerSettings
                authToken <- callFetchTokenAPI manager 
                -- putStrLn $ show authToken
                ref <- newIORef authToken
                _ <- forkIO $ fetchAndUpdateRedisAuthToken ref manager
                return cInfo {maybeAuthTokenRef = Just (ShowableIORefText ref)}
            _ -> return cInfo
    NonClusteredConnection <$> createPool (createConnection newConnInfo) PP.disconnect 1 connectMaxIdleTime connectMaxConnections

-- |Constructs a 'Connection' pool to a Redis server designated by the
--  given 'ConnectInfo', then tests if the server is actually there.
--  Throws an exception if the connection to the Redis server can't be
--  established.
checkedConnect :: ConnectInfo -> IO Connection
checkedConnect connInfo = do
    putStrLn "inside checkedConnect"
    conn <- connect connInfo
    runRedis conn $ void ping
    return conn

-- |Destroy all idle resources in the pool.
disconnect :: Connection -> IO ()
disconnect (NonClusteredConnection pool) = destroyAllResources pool
disconnect (ClusteredConnection _ conn) = Cluster.destroyNodeResources conn

-- | Memory bracket around 'connect' and 'disconnect'.
withConnect :: (Catch.MonadMask m, MonadIO m) => ConnectInfo -> (Connection -> m c) -> m c
withConnect connInfo = Catch.bracket (liftIO $ connect connInfo) (liftIO . disconnect)

-- | Memory bracket around 'checkedConnect' and 'disconnect'
withCheckedConnect :: ConnectInfo -> (Connection -> IO c) -> IO c
withCheckedConnect connInfo = bracket (checkedConnect connInfo) disconnect

-- |Interact with a Redis datastore specified by the given 'Connection'.
--
--  Each call of 'runRedis' takes a network connection from the 'Connection'
--  pool and runs the given 'Redis' action. Calls to 'runRedis' may thus block
--  while all connections from the pool are in use.
runRedis :: Connection -> Redis a -> IO a
runRedis (NonClusteredConnection pool) redis =
  withResource pool $ \conn -> runRedisInternal conn redis
runRedis (ClusteredConnection bootstrapConnInfo conn) redis =
    runRedisClusteredInternal conn (refreshShardMap bootstrapConnInfo conn) redis

newtype ClusterConnectError = ClusterConnectError Reply
    deriving (Eq, Show, Typeable)

instance Exception ClusterConnectError

data MaybeException = MaybeException String deriving (Show)

instance Exception MaybeException

data GoogleOAuthAccessTokenResponse =
  GoogleOAuthAccessTokenSuccessResponse
    { access_token :: Text
    , scope :: Maybe Text
    , expires_in :: Text
    , token_type :: Text
    }
  | GoogleOAuthAccessTokenFailureResponse
    { error :: Text
    , error_description :: Text
    }
  deriving (Show, Eq, Generic)

instance A.FromJSON GoogleOAuthAccessTokenResponse where
  parseJSON = withObject "GoogleOAuthAccessTokenResponse" $ \v ->
    (GoogleOAuthAccessTokenSuccessResponse
      <$> v .: "access_token"
      <*> v .:? "scope"
      <*> v .: "expires_in"
      <*> v .: "token_type")
    <|>
    (GoogleOAuthAccessTokenFailureResponse
      <$> v .: "error"
      <*> v .: "error_description")

data GoogleOAuthException = GoogleOAuthException String
  deriving (Show)

instance Exception GoogleOAuthException

fromJustErr :: String -> Maybe a -> IO a
fromJustErr errMsg maybeValue = case maybeValue of
    Just value -> return value
    Nothing    -> throwIO (MaybeException errMsg)

getGoogleOAuthJOSEHeader :: Text -> JWT.Algorithm -> JWT.JOSEHeader
getGoogleOAuthJOSEHeader typ alg =
  JWT.JOSEHeader
    { JWT.typ = Just typ
    , JWT.cty = Nothing
    , JWT.alg = Just alg
    , JWT.kid = Nothing
    }

getPOSIXSecondsTimestamp :: IO Int
getPOSIXSecondsTimestamp = floor . DT.utcTimeToPOSIXSeconds <$> DT.getCurrentTime

getGoogleOAuthJWTClaimsSet :: IO JWT.JWTClaimsSet
getGoogleOAuthJWTClaimsSet = do
  currentTimestamp <- getPOSIXSecondsTimestamp
  tokenExpiry <- fromMaybe 45 . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_TOKEN_EXPIRY"
  issuer <- T.pack . fromMaybe "upi-callbacks@jp-dev-chaos.iam.gserviceaccount.com" . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_ISSUER"
  subject <- T.pack . fromMaybe "upi-callbacks@jp-dev-chaos.iam.gserviceaccount.com" . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_SUBJECT"
  audience <- T.pack . fromMaybe "https://oauth2.googleapis.com/token" . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_AUDIENCE"
  scope <- T.pack . fromMaybe "https://www.googleapis.com/auth/nbupayments" . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_SCOPE"
  let iat = fromInteger (toInteger currentTimestamp)
      exp' = fromInteger (toInteger (currentTimestamp + tokenExpiry * 60))
  return
    JWT.JWTClaimsSet
      { JWT.iss = JWT.stringOrURI issuer
      , JWT.sub = JWT.stringOrURI subject
      , JWT.aud = Left <$> JWT.stringOrURI audience
      , JWT.exp = JWT.numericDate (exp' :: DT.NominalDiffTime)
      , JWT.nbf = Nothing
      , JWT.iat = JWT.numericDate (iat :: DT.NominalDiffTime)
      , JWT.jti = Nothing
      , JWT.unregisteredClaims = JWT.ClaimsMap $ DMS.singleton "scope" (A.String $ scope)
      }

getGoogleOAuthSigner :: IO (Maybe JWT.Signer)
getGoogleOAuthSigner = fmap JWT.RSAPrivateKey <$> getGoogleOAuthPrivateKey

getGoogleOAuthPrivateKey :: IO (Maybe RSAT.PrivateKey)
getGoogleOAuthPrivateKey = do
  filePath <- fromMaybe "/Users/piyush.choudhary/repos/haskull/helloworld/gpay-oauth-d.txt" . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_PRIVATE_KEY"
  let fileData = T.readFile filePath
      key = T.encodeUtf8 . T.replace (T.pack "\\n") (T.pack "\n") <$> fileData
  JWT.readRsaSecret <$> key

createGoogleOAuthATReq :: IO A.Value
createGoogleOAuthATReq = do
    let header = getGoogleOAuthJOSEHeader "JWT" JWT.RS256
    googleOAuthSigner <- getGoogleOAuthSigner
    key <- fromJustErr "getGoogleOAuthSignedJWT-key" googleOAuthSigner
    jwt <- JWT.encodeSigned key header <$> getGoogleOAuthJWTClaimsSet
    grantType <- T.pack . fromMaybe "urn:ietf:params:oauth:grant-type:jwt-bearer" . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_GRANT_TYPE"
    let googleOAuthATReq = A.object ["grant_type" A..= (grantType :: Text), "assertion" A..= jwt]
    return googleOAuthATReq

callFetchTokenAPI :: Manager -> IO Text
callFetchTokenAPI manager = do
    -- putStrLn "inside callFetchTokenAPI"
    req <- createGoogleOAuthATReq
    googleOAuthTokenUrl <- fromMaybe "http://localhost:3000/get-pass" . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_TOKEN_URL"
    initialRequest <- parseRequest googleOAuthTokenUrl
    let googleOAuthATReq = initialRequest { method = "POST", requestBody = RequestBodyLBS $ A.encode req , requestHeaders = [(hContentType, "application/json")]}
    responseOauth <- httpLbs googleOAuthATReq manager
    -- putStrLn $ "The status code was: " ++ (show $ statusCode $ responseStatus responseOauth)
    putStrLn $ show $ responseBody responseOauth
    let resBody =  A.eitherDecode (responseBody responseOauth) :: Either String GoogleOAuthAccessTokenResponse
    case resBody of
        Left err -> do
            -- putStrLn "err"
            -- putStrLn err
            throwIO $ GoogleOAuthException err
        Right (GoogleOAuthAccessTokenSuccessResponse accessToken _ _ _) -> return accessToken
        Right (GoogleOAuthAccessTokenFailureResponse _ _) -> throwIO $ GoogleOAuthException "err"

callAPIWithExceptionHandling :: Manager -> IO (Either SomeException Text)
callAPIWithExceptionHandling manager = try $ callFetchTokenAPI manager

fetchAndUpdateRedisAuthToken :: IORef Text -> Manager -> IO ()
fetchAndUpdateRedisAuthToken ref manager = do
    authTokenFetchInterval <- fromMaybe 500000 . (>>= readMaybe) <$> lookupEnv "AUTHTOKEN_FETCH_INTERVAL"
    -- putStrLn "inside fetchAndUpdateRedisAuthToken"
    forever $ do
        -- putStrLn "fetchAndUpdateRedisAuthToken running"
        authToken <- callAPIWithExceptionHandling manager
        case authToken of
            Right authToken' -> writeIORef ref authToken'
            Left ex -> putStrLn $ "Caught exception: " ++ show ex
        threadDelay authTokenFetchInterval

-- |Constructs a 'ShardMap' of connections to clustered nodes. The argument is
-- a 'ConnectInfo' for any node in the cluster
--
-- Some Redis commands are currently not supported in cluster mode
-- - CONFIG, AUTH
-- - SCAN
-- - MOVE, SELECT
-- - PUBLISH, SUBSCRIBE, PSUBSCRIBE, UNSUBSCRIBE, PUNSUBSCRIBE, RESET
connectCluster :: ConnectInfo -> IO Connection
connectCluster bootstrapConnInfo@ConnInfo{connectMaxConnections,connectMaxIdleTime,isDynamicAuthRequired} = do
    putStrLn "ClusteredConnection"
    -- putStrLn $ show bootstrapConnInfo
    newConnInfo <-
        case isDynamicAuthRequired of
            Just True -> do
                manager <- newManager tlsManagerSettings
                authToken <- callFetchTokenAPI manager 
                -- putStrLn $ show authToken
                ref <- newIORef authToken
                _ <- forkIO $ fetchAndUpdateRedisAuthToken ref manager
                return bootstrapConnInfo {maybeAuthTokenRef = Just (ShowableIORefText ref)}
            _ -> return bootstrapConnInfo
    conn <- createConnection newConnInfo
    slotsResponse <- runRedisInternal conn clusterSlots
    shardMap <- case slotsResponse of
        Left e -> throwIO $ ClusterConnectError e
        Right slots -> do
            -- putStrLn $ show slots
            shardMapFromClusterSlotsResponse slots
    commandInfos <- runRedisInternal conn command
    case commandInfos of
        Left e -> throwIO $ ClusterConnectError e
        Right infos -> do
            let withAuth = connectWithAuth newConnInfo
            clusterConnection <- Cluster.createClusterConnectionPools withAuth connectMaxConnections connectMaxIdleTime infos shardMap
            return $ ClusteredConnection newConnInfo clusterConnection

connectWithAuth :: ConnectInfo -> Cluster.Host -> CC.PortID -> IO CC.ConnectionContext
connectWithAuth ConnInfo{connectTLSParams,connectAuth,connectReadOnly,connectTimeout,maybeAuthTokenRef} host port = do
    conn <- PP.connect host port $ clusterConnectTimeoutinUs <$> connectTimeout
    conn' <- case connectTLSParams of
                Nothing -> return conn
                Just tlsParams -> PP.enableTLS tlsParams conn
    PP.beginReceiving conn'
    -- putStrLn $ ("Making new connection in authfun with port" ) <> show port
    connectAuth' <- 
        case maybeAuthTokenRef of
            Just (ShowableIORefText authTokenRef) -> do
                authToken <- readIORef authTokenRef
                return $ Just $ T.encodeUtf8 authToken
            _ -> return connectAuth
    putStrLn $ "connectWithAuth: redis pass is" <> show connectAuth'
    runRedisInternal conn' $ do
        -- AUTH
        case connectAuth' of
            Nothing   -> return ()
            Just pass -> do
                resp <- auth pass
                case resp of
                    Left r -> liftIO $ throwIO $ ConnectAuthError r
                    _      -> return ()
    when connectReadOnly $ do
        runRedisInternal conn' readOnly >> return()
    return $ PP.toCtx conn'

clusterConnectTimeoutinUs :: Time.NominalDiffTime -> Int
clusterConnectTimeoutinUs = round . (1000000 *) 

shardMapFromClusterSlotsResponse :: ClusterSlotsResponse -> IO ShardMap
shardMapFromClusterSlotsResponse ClusterSlotsResponse{..} = ShardMap <$> foldr mkShardMap (pure IntMap.empty)  clusterSlotsResponseEntries where
    mkShardMap :: ClusterSlotsResponseEntry -> IO (IntMap.IntMap Shard) -> IO (IntMap.IntMap Shard)
    mkShardMap ClusterSlotsResponseEntry{..} accumulator = do
        accumulated <- accumulator
        let master = nodeFromClusterSlotNode True clusterSlotsResponseEntryMaster
        -- let replicas = map (nodeFromClusterSlotNode False) clusterSlotsResponseEntryReplicas
        let shard = Shard master []
        let slotMap = IntMap.fromList $ map (, shard) [clusterSlotsResponseEntryStartSlot..clusterSlotsResponseEntryEndSlot]
        return $ IntMap.union slotMap accumulated
    nodeFromClusterSlotNode :: Bool -> ClusterSlotsNode -> Node
    nodeFromClusterSlotNode isMaster ClusterSlotsNode{..} =
        let hostname = Char8.unpack clusterSlotsNodeIP
            role = if isMaster then Cluster.Master else Cluster.Slave
        in
            Cluster.Node clusterSlotsNodeID role hostname (toEnum clusterSlotsNodePort)

refreshShardMap :: ConnectInfo -> Cluster.Connection ->  IO ShardMap
refreshShardMap connectInfo@ConnInfo{connectMaxConnections,connectMaxIdleTime} (Cluster.Connection shardNodeVar _ _) = do
    modifyMVar shardNodeVar $ \(_, oldNodeConnMap) -> do
        newShardMap <- refreshShardMapWithNodeConn (HM.elems oldNodeConnMap)
        newNodeConnMap <- updateNodeConnections newShardMap oldNodeConnMap        
        return ((newShardMap, newNodeConnMap), newShardMap)
    where
        withAuth :: Cluster.Host -> CC.PortID -> IO CC.ConnectionContext
        withAuth = connectWithAuth connectInfo
        updateNodeConnections :: ShardMap -> HM.HashMap Cluster.NodeID Cluster.NodeConnection -> IO (HM.HashMap Cluster.NodeID Cluster.NodeConnection)
        updateNodeConnections newShardMap oldNodeConnMap = do
            foldM (\acc node@(Cluster.Node nodeid _ _ _) -> 
                case HM.lookup nodeid oldNodeConnMap of
                    Just nodeconn -> return $ HM.insert nodeid nodeconn acc
                    Nothing       -> do
                        (_,nodeConnPool) <- Cluster.createNodePool withAuth connectMaxConnections connectMaxIdleTime node
                        return $ HM.insert nodeid nodeConnPool acc
                 ) HM.empty (nub $ Cluster.nodes newShardMap)

refreshShardMapWithNodeConn :: [Cluster.NodeConnection] -> IO ShardMap
refreshShardMapWithNodeConn [] = throwIO $ ClusterConnectError (Error "Couldn't refresh shardMap due to connection error")
refreshShardMapWithNodeConn nodeConnsList = do
    let numOfNodes = length nodeConnsList
    selectedIdx <- randomRIO (0, length nodeConnsList - 1)
    let (Cluster.NodeConnection pool _) = nodeConnsList !! selectedIdx
    eresp <- try $ refreshShardMapWithPool pool
    case eresp of 
        Left  (_::SomeException) ->  do                 -- retry on other node
            let otherSelectedIdx                        = (selectedIdx + 1) `mod` numOfNodes
                (Cluster.NodeConnection otherPool _)    = nodeConnsList !! otherSelectedIdx
            refreshShardMapWithPool otherPool
        Right shardMap -> return shardMap
    where 
        refreshShardMapWithPool pool = withResource pool $ 
                \(ctx,_) -> do
                    pipelineConn <- PP.fromCtx ctx
                    envTimeout <- fromMaybe (10 ^ (5 :: Int)) . (>>= readMaybe) <$> lookupEnv "REDIS_CLUSTER_SLOTS_TIMEOUT"
                    eresp <- T.timeout envTimeout (try $ refreshShardMapWithConn pipelineConn True) -- racing with delay of default 100 ms 
                    case eresp of
                        Nothing -> do
                            print $ "TimeoutForConnection " <> show ctx 
                            throwIO $ Cluster.TimeoutException "ClusterSlots Timeout"
                        Just eiShardMapResp -> 
                            case eiShardMapResp of
                                Right shardMap -> pure shardMap 
                                Left (err :: SomeException) -> do
                                    print $ "ShardMapRefreshError-" <> show err 
                                    throwIO $ ClusterConnectError (Error "Couldn't refresh shardMap due to connection error")

refreshShardMapWithConn :: PP.Connection -> Bool -> IO ShardMap
refreshShardMapWithConn pipelineConn _ = do
    _ <- PP.beginReceiving pipelineConn
    slotsResponse <- runRedisInternal pipelineConn clusterSlots
    case slotsResponse of
        Left e -> throwIO $ ClusterConnectError e
        Right slots -> case clusterSlotsResponseEntries slots of 
            [] -> throwIO $ ClusterConnectError $ SingleLine "empty slotsResponse"
            _ -> shardMapFromClusterSlotsResponse slots
