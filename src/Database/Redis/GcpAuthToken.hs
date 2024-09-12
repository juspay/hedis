{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
module Database.Redis.GcpAuthToken where

import Control.Exception as CE
import Control.Monad(forever)
import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)
import Text.Read (readMaybe)
import Network.HTTP.Client
-- import Network.HTTP.Client.TLS
import Data.Aeson as A hiding (Error)
import Data.Text as T (replace, pack, Text, unpack)
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import Network.HTTP.Types.Header
import qualified Web.JWT as JWT
import qualified Crypto.PubKey.RSA.Types as RSAT
import qualified Data.Time as DT
import qualified Data.Time.Clock.POSIX as DT
import qualified Data.Map.Strict as DMS
import Data.IORef
import Control.Concurrent
import GHC.Generics
import Control.Applicative
--------------------------------------------------------------------------------

newtype ShowableIORefText = ShowableIORefText (IORef Text)

instance Show ShowableIORefText where
    show _ = "ioref text" :: String

data MaybeException = MaybeException String deriving (Show)

instance Exception MaybeException

data GoogleOAuthAccessTokenResponse =
  GoogleOAuthAccessTokenSuccessResponse
    { access_token :: Text
    , scope :: Maybe Text
    , expires_in :: Int
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
  issuer <- T.pack . fromMaybe "upi-callbacks@jp-dev-chaos.iam.gserviceaccount.com"  <$> lookupEnv "GOOGLE_OAUTH_ISSUER"
  subject <- T.pack . fromMaybe "upi-callbacks@jp-dev-chaos.iam.gserviceaccount.com" <$> lookupEnv "GOOGLE_OAUTH_SUBJECT"
  audience <- T.pack . fromMaybe "https://oauth2.googleapis.com/token" <$> lookupEnv "GOOGLE_OAUTH_AUDIENCE"
  scope <- T.pack . fromMaybe "https://www.googleapis.com/auth/nbupayments" <$> lookupEnv "GOOGLE_OAUTH_SCOPE"
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
  filePath <- fromMaybe "/Users/piyush.choudhary/repos/haskull/helloworld/gpay-oauth-d.txt"  <$> lookupEnv "GOOGLE_OAUTH_PRIVATE_KEY"
  let fileData = T.readFile filePath
      key = T.encodeUtf8 . T.replace (T.pack "\\n") (T.pack "\n") <$> fileData
  JWT.readRsaSecret <$> key

createGoogleOAuthATReq :: IO A.Value
createGoogleOAuthATReq = do
    let header = getGoogleOAuthJOSEHeader "JWT" JWT.RS256
    googleOAuthSigner <- getGoogleOAuthSigner
    key <- fromJustErr "getGoogleOAuthSignedJWT-key" googleOAuthSigner
    jwt <- JWT.encodeSigned key header <$> getGoogleOAuthJWTClaimsSet
    grantType <- T.pack . fromMaybe "urn:ietf:params:oauth:grant-type:jwt-bearer" <$> lookupEnv "GOOGLE_OAUTH_GRANT_TYPE"
    let googleOAuthATReq = A.object ["grant_type" A..= (grantType :: Text), "assertion" A..= jwt]
    return googleOAuthATReq

callFetchTokenAPI :: Manager -> IO Text
callFetchTokenAPI manager = do
    -- putStrLn "inside callFetchTokenAPI"
    req <- createGoogleOAuthATReq
    googleOAuthTokenUrl <- fromMaybe "https://oauth2.googleapis.com/token" <$> lookupEnv "GOOGLE_OAUTH_TOKEN_URL"
    initialRequest <- parseRequest googleOAuthTokenUrl
    let googleOAuthATReq = initialRequest { method = "POST", requestBody = RequestBodyLBS $ A.encode req , requestHeaders = [(hContentType, "application/json")]}
    responseOauth <- httpLbs googleOAuthATReq manager
    -- putStrLn $ "The status code was: " ++ (show $ statusCode $ responseStatus responseOauth)
    putStrLn $ show $ responseBody responseOauth
    let resBody =  A.eitherDecode (responseBody responseOauth) :: Either String GoogleOAuthAccessTokenResponse
    case resBody of
        Left err -> throwIO (GoogleOAuthException err)
        Right (GoogleOAuthAccessTokenSuccessResponse accessToken _ _ _) -> return accessToken
        Right (GoogleOAuthAccessTokenFailureResponse err _) -> throwIO (GoogleOAuthException $ unpack err)

callAPIWithExceptionHandling :: Manager -> IO (Either SomeException Text)
callAPIWithExceptionHandling manager = try $ callFetchTokenAPI manager

fetchAndUpdateRedisAuthToken :: IORef Text -> Manager -> IO ()
fetchAndUpdateRedisAuthToken ref manager = do
    authTokenFetchInterval <- fromMaybe 500000 . (>>= readMaybe) <$> lookupEnv "AUTHTOKEN_FETCH_INTERVAL"
    forever $ do
        authToken <- callAPIWithExceptionHandling manager
        case authToken of
            Right authToken' -> writeIORef ref authToken'
            Left ex -> putStrLn $ "Caught exception in fetchAndUpdateRedisAuthToken: " ++ show ex
        threadDelay authTokenFetchInterval