{-# LANGUAGE OverloadedStrings, LambdaCase #-}

module ClusterBenchmark where

import Control.Concurrent
import Control.Monad
import Control.Monad.Trans
import Data.Time
import Database.Redis hiding (append)
import Text.Printf
import qualified Data.ByteString.Char8 as BS
import System.Random (randomRIO)

nRequests, nClients :: Int
nRequests = 30000
nClients  = 150


clusterBenchMark :: IO ()
clusterBenchMark = do
    ----------------------------------------------------------------------
    -- Preparation
    --
    conn <- connectCluster defaultClusterConnectInfo
    runRedis conn $ do
        _ <- flushall
        _ <- ping >>= \case
          Right _ -> return ()
          Left e -> error $ show e
        _ <- del ["somestream"]
        _ <- del ["somestream1"]
        xadd "somestream" "123" (keyValueGenerator 50 "k" "v")>>= \case
          Left x -> error $ show x
          _ -> do
            sadd "k51" ["v51"] >>= \case
                Left _ -> error "error"
                _ -> return ()
        return ()
    
    ----------------------------------------------------------------------
    -- Spawn clients
    --
    start <- newEmptyMVar
    done  <- newEmptyMVar
    replicateM_ nClients $ forkIO $ do
        forever $ do
          (reps,action) <- liftIO $ takeMVar start
          replicateM_ reps $ runRedis conn action
          liftIO $ putMVar done ()
    
    let timeAction name nActions action = do
          startT <- getCurrentTime
          -- each clients runs ACTION nRepetitions times
          let nRepetitions = nRequests `div` nClients `div` nActions
          replicateM_ nClients $ putMVar start (nRepetitions,action)
          replicateM_ nClients $ takeMVar done
          stopT <- getCurrentTime
          let deltaT     = realToFrac $ diffUTCTime stopT startT
              -- the real # of reqs send. We might have lost some due to 'div'.
              actualReqs = nRepetitions * nActions * nClients
              rqsPerSec  = fromIntegral actualReqs / deltaT :: Double
          putStrLn $ printf "%-20s %10.2f Req/s" (name :: String) rqsPerSec

    ----------------------------------------------------------------------
    -- Benchmarks
    --
    timeAction "ping" 1 $ do
        ping >>= \case
          Right Pong -> return ()
          _ -> error "error"
        return ()
    
    timeAction "ping (pipelined)" 100 $ do
        pongs <- replicateM 100 ping
        let expected = replicate 100 (Right Pong)
        case pongs == expected of
              True -> return ()
              _ -> error "error"
        return ()


    timeAction "get" 1 $ do
        get "key" >>= \case
          Right Nothing -> return ()
          _ -> error "error"
        return ()

    timeAction "get random keys" 1 $ do
        key <- randomRIO (0::Int, 16000)
        get (BS.pack (show key)) >>= \case
          Right Nothing -> return ()
          _ -> error "error"
        return ()
    
    timeAction "get pipelined 10" 10 $ do
        res <- replicateM 10 (get "k1")
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()
    
    timeAction "get pipelined 100" 100 $ do
        res <- replicateM 10 (get "k1")
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()
    
    timeAction "get pipelined 1000" 1000 $ do
        res <- replicateM 10 (get "k1")
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()
    
    timeAction "smembers get 1" 1 $ do
        smembers "k51" >>= \case
          Right _ -> return ()
          _ -> error "error"
        return ()

    timeAction "smembers get 10" 10 $ do
        res <- replicateM 10 (smembers "k51")
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()

    timeAction "smembers get 100" 100 $ do
        res <- replicateM 100 (smembers "k51")
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()

    timeAction "smembers get 1000" 1000 $ do
        res <- replicateM 1000 (smembers "k51")
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()
    
    timeAction "sadd 1" 1 $ do
        res <- sequence $ map (\ (x, v) -> sadd x v ) $ keyListValueGenerator 1 1 ("kt"::BS.ByteString) ("vt"::BS.ByteString)
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()

    get100Keys <- pure $ keyListValueGenerator 100 1 ("kt"::BS.ByteString) ("vt"::BS.ByteString)

    timeAction "sadd 100" 1 $ do
        res <- sequence $ map (\ (x, v) -> sadd x v ) $ get100Keys
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()

    -- timeAction "xadd 1" 1 $ do
    --     res <- xadd "somestream1" "1234" $ keyValueGenerator 1 ("kt"::BS.ByteString) ("vt"::BS.ByteString)
    --     case res of
    --       Right _ -> return ()
    --       Left _ -> error "error"
    --     return ()

    -- timeAction "xadd 100" 1 $ do
    --     res <- replicateM 100 (xadd "somestream" "123" $ keyValueGenerator 1 ("kt"::BS.ByteString) ("vt"::BS.ByteString))
    --     case sequence res of
    --       Right _ -> return ()
    --       _ -> error "error"
    --     return ()

    timeAction "setex 1" 1 $ do
        res <- sequence $ map (\ (x, v) -> setex x 1 v ) $ keyValueGenerator 1 ("kt"::BS.ByteString) ("vt"::BS.ByteString)
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()

    timeAction "setex 100" 1 $ do
        res <- sequence $ map (\ (x, v) -> setex x 1 v ) $ keyValueGenerator 100 ("kt"::BS.ByteString) ("vt"::BS.ByteString)
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()

    timeAction "del 1" 1 $ do
        res <- sequence $ map (\x -> del x ) $ [["kto1"::BS.ByteString]]
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()

    timeAction "del 100" 100 $ do
        res <- sequence $ map (\x -> del [x] ) $ keyGenerator 100 ("kt"::BS.ByteString)
        case sequence res of
          Right _ -> return ()
          _ -> error "error"
        return ()


keyGenerator :: Int -> BS.ByteString -> [BS.ByteString]
keyGenerator 0 _  = []
keyGenerator x key =
    let bSx = (BS.pack $ show x)
    in [BS.append key bSx] <> keyGenerator (x-1) key


keyValueGenerator :: Int -> BS.ByteString -> BS.ByteString -> [(BS.ByteString, BS.ByteString)]
keyValueGenerator 0 _ _  = []
keyValueGenerator x key val =
    let bSx = (BS.pack $ show x)
    in [(BS.append key bSx, BS.append val bSx)] <> keyValueGenerator (x-1) key val


keyListValueGenerator :: Int -> Int -> BS.ByteString -> BS.ByteString -> [(BS.ByteString, [BS.ByteString])]
keyListValueGenerator 0 _ _ _  = []
keyListValueGenerator keyL valL key val =
    let bSKeyL = (BS.pack $ show keyL)
    in [(BS.append key bSKeyL, getValueList (BS.append val bSKeyL))] <> keyListValueGenerator (keyL-1) valL key val
    where
        getValueList value = map (\ x -> BS.append value (BS.pack $ show x)) [1..valL]
