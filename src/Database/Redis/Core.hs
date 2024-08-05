{-# LANGUAGE OverloadedStrings, GeneralizedNewtypeDeriving, RecordWildCards,
    MultiParamTypeClasses, FunctionalDependencies, FlexibleInstances, CPP,
    DeriveDataTypeable, StandaloneDeriving #-}

module Database.Redis.Core (
    Redis(), unRedis, reRedis,
    RedisCtx(..), MonadRedis(..),
    send, recv, sendRequest, sendToAllMasterNodes,
    runRedisInternal,
    runRedisClusteredInternal,
    runRedisInternalDebug,
    runRedisClusteredInternalDebug,
    RedisEnv(..),
) where

import Prelude
#if __GLASGOW_HASKELL__ < 710
import Control.Applicative
#endif
import Control.Concurrent.MVar (newMVar)
import Control.Monad.Reader
import qualified Data.ByteString as B
import Data.IORef
import Database.Redis.Core.Internal
import Database.Redis.Protocol
import qualified Database.Redis.ProtocolPipelining as PP
import Database.Redis.Types
import Database.Redis.Cluster(ShardMap)
import qualified Database.Redis.Cluster as Cluster
import qualified Data.ByteString.UTF8 as BUTF

--------------------------------------------------------------------------------
-- The Redis Monad
--

-- |This class captures the following behaviour: In a context @m@, a command
--  will return its result wrapped in a \"container\" of type @f@.
--
--  Please refer to the Command Type Signatures section of this page for more
--  information.
class (MonadRedis m) => RedisCtx m f | m -> f where
    returnDecode :: RedisResult a => Reply -> m (f a)

class (Monad m) => MonadRedis m where
    liftRedis :: Redis a -> m a


instance RedisCtx Redis (Either Reply) where
    returnDecode = return . decode

instance MonadRedis Redis where
    liftRedis = id

-- |Deconstruct Redis constructor.
--
--  'unRedis' and 'reRedis' can be used to define instances for
--  arbitrary typeclasses.
--
--  WARNING! These functions are considered internal and no guarantee
--  is given at this point that they will not break in future.
unRedis :: Redis a -> ReaderT RedisEnv IO a
unRedis (Redis r) = r

-- |Reconstruct Redis constructor.
reRedis :: ReaderT RedisEnv IO a -> Redis a
reRedis r = Redis r

-- |Internal version of 'runRedis' that does not depend on the 'Connection'
--  abstraction. Used to run the AUTH command when connecting.
runRedisInternal :: PP.Connection -> Redis a -> IO a
runRedisInternal conn (Redis redis) = do
  -- Dummy reply in case no request is sent.
  ref <- newIORef (SingleLine "nobody will ever see this")
  r <- runReaderT redis (NonClusteredEnv conn ref Nothing)
  -- Evaluate last reply to keep lazy IO inside runRedis.
  readIORef ref >>= (`seq` return ())
  return r

runRedisInternalDebug :: PP.Connection -> Redis a -> IO (a,String)
runRedisInternalDebug conn (Redis redis) = do
    -- Dummy reply in case no request is sent.
    ref <- newIORef (SingleLine "nobody will ever see this")
    rawCmd' <- newIORef mempty
    r <- runReaderT redis (NonClusteredEnv conn ref (Just rawCmd'))
    rQ' <- readIORef rawCmd'
    -- Evaluate last reply to keep lazy IO inside runRedis.
    readIORef ref >>= (`seq` return ())
    return (r,rQ')

runRedisClusteredInternal :: Cluster.Connection -> IO ShardMap -> Redis a -> IO a
runRedisClusteredInternal connection refreshShardmapAction (Redis redis) = do
    ref <- newIORef (SingleLine "nobody will ever see this")
    stateVar <- liftIO $ newMVar $ Cluster.Pending []
    pipelineVar <- liftIO $ newMVar $ Cluster.Pipeline stateVar
    r <- runReaderT redis (ClusteredEnv refreshShardmapAction connection ref pipelineVar Nothing) 
    readIORef ref >>= (`seq` return ())
    return r

runRedisClusteredInternalDebug :: Cluster.Connection -> IO ShardMap -> Redis a -> IO (a,String)
runRedisClusteredInternalDebug connection refreshShardmapAction (Redis redis) = do
    ref <- newIORef (SingleLine "runRedisClusteredInternalDebug nobody will ever see this")
    stateVar <- liftIO $ newMVar $ Cluster.Pending []
    pipelineVar <- liftIO $ newMVar $ Cluster.Pipeline stateVar
    rawCmdCluster' <- newIORef mempty
    r <- runReaderT redis (ClusteredEnv refreshShardmapAction connection ref pipelineVar (Just rawCmdCluster'))
    rQ' <- readIORef rawCmdCluster'
    r `seq` return ()
    return (r,rQ')

setLastReply :: Reply -> ReaderT RedisEnv IO ()
setLastReply r = do
  ref <- asks envLastReply
  lift (writeIORef ref r)

recv :: (MonadRedis m) => m Reply
recv = liftRedis $ Redis $ do
  conn <- asks envConn
  r <- liftIO (PP.recv conn)
  setLastReply r
  return r

send :: (MonadRedis m) => [B.ByteString] -> m ()
send req = liftRedis $ Redis $ do
    conn <- asks envConn
    liftIO $ PP.send conn (renderRequest req)

-- |'sendRequest' can be used to implement commands from experimental
--  versions of Redis. An example of how to implement a command is given
--  below.
--
-- @
-- -- |Redis DEBUG OBJECT command
-- debugObject :: ByteString -> 'Redis' (Either 'Reply' ByteString)
-- debugObject key = 'sendRequest' [\"DEBUG\", \"OBJECT\", key]
-- @
--
sendRequest :: (RedisCtx m f, RedisResult a)
    => [B.ByteString] -> m (f a)
sendRequest req = do
    r' <- liftRedis $ Redis $ do
        env <- ask
        _ <- liftIO $ extractQuery env req
        case env of
            NonClusteredEnv{..} -> do
                r <- liftIO $ PP.request envConn (renderRequest req)
                setLastReply r
                return r
            ClusteredEnv{..} -> do
                r <- liftIO $ Cluster.requestPipelined refreshAction connection req pipeline
                lift (writeIORef clusteredLastReply r)
                return r
    returnDecode r'

sendToAllMasterNodes :: (RedisResult a, MonadRedis m) => [B.ByteString] -> m [Either Reply a]
sendToAllMasterNodes req = do
    r' <- liftRedis $ Redis $ do
        env <- ask
        case env of 
            NonClusteredEnv{..} -> do
                r <- liftIO $ PP.request envConn (renderRequest req)
                r `seq` return [r]
            ClusteredEnv{..} ->  do
                r <- liftIO $ Cluster.requestMasterNodes connection req
                return r
    return $ map decode r'



extractQuery :: RedisEnv -> [B.ByteString] -> IO (Maybe String) 
extractQuery  NonClusteredEnv{..} query = extractQueryHelper rawCmd query
extractQuery ClusteredEnv{..} query = extractQueryHelper rawCmdCluster query
    
extractQueryHelper :: Maybe (IORef String) -> [B.ByteString] -> IO (Maybe String)
extractQueryHelper maybeStr query = 
        case maybeStr of
        Nothing -> return Nothing
        Just rw -> do
            let resp = foldr (\x acc -> BUTF.toString x <> " " ++ acc) "" query
            _ <- atomicModifyIORef' rw $ \cmd -> (resp,cmd)
            return $ Just resp
    