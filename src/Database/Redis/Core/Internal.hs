{-# LANGUAGE CPP #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Database.Redis.Core.Internal where
#if __GLASGOW_HASKELL__ > 711 && __GLASGOW_HASKELL__ < 808
import Control.Monad.Fail (MonadFail)
#endif
import Control.Monad.Reader
import Data.IORef
import Database.Redis.Protocol
import qualified Database.Redis.ProtocolPipelining as PP

-- |Context for normal command execution, outside of transactions. Use
--  'runRedis' to run actions of this type.
--
--  In this context, each result is wrapped in an 'Either' to account for the
--  possibility of Redis returning an 'Error' reply.
newtype Redis a =
  Redis (ReaderT RedisEnv IO a)
  deriving (Monad, MonadIO, Functor, Applicative)
#if __GLASGOW_HASKELL__ > 711
deriving instance MonadFail Redis
#endif
data RedisEnv =
  Env
    { envConn :: PP.Connection
    , envLastReply :: IORef Reply
    }
