{-# LANGUAGE TupleSections #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NamedFieldPuns #-}
module Database.Redis.Connection where

import Control.Exception
import qualified Control.Monad.Catch as Catch
import Control.Monad.IO.Class(liftIO, MonadIO)
import Control.Monad(when)
import Control.Concurrent(forkIO)
import Control.Concurrent.MVar(MVar, newMVar, putMVar, readMVar, modifyMVar_)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as Char8
import Data.Functor(void)
import qualified Data.IntMap.Strict as IntMap
import Data.Pool(Pool, withResource, createPool, destroyAllResources)
import Data.Typeable
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
import Database.Redis.Cluster(ShardMap(..), Node, Shard(..))
import qualified Database.Redis.Cluster as Cluster
import qualified Database.Redis.ConnectionContext as CC
import           Control.Concurrent (threadDelay)
import           Control.Concurrent.Async (race)
--import qualified Database.Redis.Cluster.Pipeline as ClusterPipeline
import qualified Data.IORef as IOR
import Data.List (nub)
import Data.Maybe (catMaybes)

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
    | ClusteredConnection (MVar ShardMap) Cluster.Connection

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
    } deriving Show

data ConnectError = ConnectAuthError Reply
                  | ConnectSelectError Reply
    deriving (Eq, Show, Typeable)

instance Exception ConnectError

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

    runRedisInternal conn' $ do
        -- AUTH
        case connectAuth of
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
connect cInfo@ConnInfo{..} = NonClusteredConnection <$>
    createPool (createConnection cInfo) PP.disconnect 1 connectMaxIdleTime connectMaxConnections

-- |Constructs a 'Connection' pool to a Redis server designated by the
--  given 'ConnectInfo', then tests if the server is actually there.
--  Throws an exception if the connection to the Redis server can't be
--  established.
checkedConnect :: ConnectInfo -> IO Connection
checkedConnect connInfo = do
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
runRedis (ClusteredConnection _ conn) redis =
    runRedisClusteredInternal conn (refreshShardMap conn) redis

newtype ClusterConnectError = ClusterConnectError Reply
    deriving (Eq, Show, Typeable)

instance Exception ClusterConnectError

-- |Constructs a 'ShardMap' of connections to clustered nodes. The argument is
-- a 'ConnectInfo' for any node in the cluster
--
-- Some Redis commands are currently not supported in cluster mode
-- - CONFIG, AUTH
-- - SCAN
-- - MOVE, SELECT
-- - PUBLISH, SUBSCRIBE, PSUBSCRIBE, UNSUBSCRIBE, PUNSUBSCRIBE, RESET
connectCluster :: ConnectInfo -> IO Connection
connectCluster bootstrapConnInfo = do
    let timeoutOptUs =
          round . (1000000 *) <$> connectTimeout bootstrapConnInfo
    conn <- createConnection bootstrapConnInfo
    slotsResponse <- runRedisInternal conn clusterSlots
    shardMapVar <- case slotsResponse of
        Left e -> throwIO $ ClusterConnectError e
        Right slots -> do
            shardMap <- shardMapFromClusterSlotsResponse slots
            newMVar shardMap
    commandInfos <- runRedisInternal conn command
    case commandInfos of
        Left e -> throwIO $ ClusterConnectError e
        Right infos -> do
            let
                isConnectionReadOnly = connectReadOnly bootstrapConnInfo
                connectTLSParams' = connectTLSParams bootstrapConnInfo
                connectAuth' = connectAuth bootstrapConnInfo
                tcpInfo = Cluster.TcpInfo {
                    connectTLSParams = connectTLSParams',
                    connectAuth      = connectAuth',
                    idleTime         = connectMaxIdleTime bootstrapConnInfo,
                    maxResources     = connectMaxConnections bootstrapConnInfo,
                    timeoutOpt       = timeoutOptUs
                }
                withAuth = tcpConnWithAuth connectAuth' connectTLSParams'
                clusterConnection = Cluster.connect withAuth infos shardMapVar isConnectionReadOnly refreshShardMapWithNodeConn tcpInfo
            -- pool <- createPool (clusterConnect isConnectionReadOnly clusterConnection) Cluster.disconnect 3 (connectMaxIdleTime bootstrapConnInfo) (connectMaxConnections bootstrapConnInfo)
            connection <- clusterConnect isConnectionReadOnly clusterConnection
            return $ ClusteredConnection shardMapVar connection
    where

      clusterConnect :: Bool -> IO Cluster.Connection -> IO Cluster.Connection
      clusterConnect readOnlyConnection connection = do
          clusterConn@(Cluster.Connection nodeMapVar _ _ _ _ _) <- connection
          nodeMap <- readMVar nodeMapVar
          let nodeList = HM.toList nodeMap
          maybeConns <- sequence $ (ctxToConn . snd) <$> nodeList
          let nodeConnsPair = zip maybeConns nodeList
          workingNodes <- mapM (\(maybeConn, nodeConn) -> case maybeConn of
                    Just conn -> do
                        when readOnlyConnection $ do
                            PP.beginReceiving conn
                            runRedisInternal conn readOnly >> return ()
                        return $ Just nodeConn
                    Nothing -> return Nothing
                ) nodeConnsPair
          let newMap = HM.fromList $ catMaybes workingNodes
          _ <- forkIO $ putMVar nodeMapVar newMap
          return clusterConn
          where
          ctxToConn :: Cluster.NodeConnection -> IO (Maybe PP.Connection)
          ctxToConn (Cluster.NodeConnection pool _ nid) = do
            maybeConn <- try $ withResource pool PP.fromCtx
            case maybeConn of
                Right ppConn -> return $ Just ppConn
                Left (_ :: SomeException) -> do
                    putStrLn ("SomeException Occured in NodeID " ++ show nid)
                    return Nothing


tcpConnWithAuth :: Maybe B.ByteString -> Maybe ClientParams -> Cluster.Host -> CC.PortID -> Maybe Int -> IO CC.ConnectionContext
tcpConnWithAuth connectAuth connectTLSParams host port timeout = do
    conn <- PP.connect host port timeout
    conn' <- case connectTLSParams of
                Nothing -> return conn
                Just tlsParams -> PP.enableTLS tlsParams conn
    PP.beginReceiving conn'

    runRedisInternal conn' $ do
        -- AUTH
        case connectAuth of
            Nothing   -> return ()
            Just pass -> do
                resp <- auth pass
                case resp of
                    Left r -> liftIO $ throwIO $ ConnectAuthError r
                    _      -> return ()
    return $ PP.toCtx conn'

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

refreshShardMap :: Cluster.Connection -> IO ShardMap
refreshShardMap (Cluster.Connection nodeConnsVar _ shardMapVar _ _ Cluster.TcpInfo { idleTime, maxResources, timeoutOpt, connectAuth, connectTLSParams }) = do
    nodeConns <- readMVar nodeConnsVar
    newShardMap <- refreshShardMapWithNodeConn (HM.elems nodeConns)
    modifyMVar_ nodeConnsVar $ \oldMap -> do
        putMVar shardMapVar newShardMap
        updateNodeConnections newShardMap oldMap
    return newShardMap
    where
        withAuth :: Cluster.Host -> CC.PortID -> Maybe Int -> IO CC.ConnectionContext
        withAuth = tcpConnWithAuth connectAuth connectTLSParams
        updateNodeConnections :: ShardMap -> HM.HashMap Cluster.NodeID Cluster.NodeConnection -> IO (HM.HashMap Cluster.NodeID Cluster.NodeConnection)
        updateNodeConnections shardMap oldMap =
            connectAndAppend oldMap $ filter ((`HM.member` oldMap) . (\(Cluster.Node n _ _ _) -> n)) (nub $ Cluster.nodes shardMap)
        connectAndAppend :: HM.HashMap Cluster.NodeID Cluster.NodeConnection -> [Cluster.Node] -> IO (HM.HashMap Cluster.NodeID Cluster.NodeConnection)
        connectAndAppend oldMap nodes = do
            conns <- mapM connectNode nodes
            return $ foldl (\acc (k, v) -> HM.insert k v acc) oldMap conns
        connectNode :: Cluster.Node -> IO (Cluster.NodeID, Cluster.NodeConnection)
        connectNode (Cluster.Node n _ host port) = do
            ctx <- createPool (withAuth host (CC.PortNumber $ toEnum port) timeoutOpt) CC.disconnect 1 idleTime maxResources
            ref <- IOR.newIORef Nothing
            return (n, Cluster.NodeConnection ctx ref n)

refreshShardMapWithNodeConn :: [Cluster.NodeConnection] -> IO ShardMap
refreshShardMapWithNodeConn [] = throwIO $ ClusterConnectError (Error "Couldn't refresh shardMap due to connection error")
refreshShardMapWithNodeConn nodeConnsList = do
    selectedIdx <- randomRIO (0, (length nodeConnsList) - 1)
    let (Cluster.NodeConnection pool _ _) = nodeConnsList !! selectedIdx
    withResource pool $ \ctx -> do
        pipelineConn <- PP.fromCtx ctx
        envTimeout <- fromMaybe (10 ^ (3 :: Int)) . (>>= readMaybe) <$> lookupEnv "REDIS_CLUSTER_SLOTS_TIMEOUT"
        raceResult <- race (threadDelay envTimeout) (try $ refreshShardMapWithConn pipelineConn True) -- racing with delay of default 1 ms 
        case raceResult of
            Left () -> do
                print $ "TimeoutForConnection " <> show ctx 
                throwIO $ Cluster.TimeoutException "ClusterSlots Timeout"
            Right eiShardMapResp -> 
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
