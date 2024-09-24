{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
module Database.Redis.GcpAuthToken where

import Control.Exception as CE
import Control.Monad(forever, join)
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

stripLensPrefixOptions :: Options
stripLensPrefixOptions = defaultOptions { fieldLabelModifier = drop 1 }

data GoogleOAuthAccessTokenRequest =
  GoogleOAuthAccessTokenRequest
    { _grant_type :: Text
    , _assertion :: Text
    }
    deriving (Show, Eq, Ord, Generic)

instance ToJSON GoogleOAuthAccessTokenRequest where
  toJSON = genericToJSON $ stripLensPrefixOptions {omitNothingFields = True}

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

getGoogleOAuthJWTClaimsSet :: Int -> Text -> Text -> Text -> Text -> IO JWT.JWTClaimsSet
getGoogleOAuthJWTClaimsSet tokenExpiry issuer subject audience scope = do
  currentTimestamp <- getPOSIXSecondsTimestamp
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

getGoogleOAuthSigner :: String -> IO (Maybe JWT.Signer)
getGoogleOAuthSigner filePath= fmap JWT.RSAPrivateKey <$> getGoogleOAuthPrivateKey filePath

getGoogleOAuthPrivateKey :: String -> IO (Maybe RSAT.PrivateKey)
getGoogleOAuthPrivateKey filePath = do
  let fileData = T.readFile filePath
      key = T.encodeUtf8 . T.replace (T.pack "\\n") (T.pack "\n") <$> fileData
  JWT.readRsaSecret <$> key

createGoogleOAuthATReq :: Int -> Text -> Text -> Text -> Text -> String -> Text -> IO A.Value
createGoogleOAuthATReq tokenExpiry issuer subject audience scope filePath grantType = do
    let header = getGoogleOAuthJOSEHeader "JWT" JWT.RS256
    googleOAuthSigner <- getGoogleOAuthSigner filePath
    key <- fromJustErr "getGoogleOAuthSignedJWT-key" googleOAuthSigner
    jwt <- JWT.encodeSigned key header <$> getGoogleOAuthJWTClaimsSet tokenExpiry issuer subject audience scope
    let googleOAuthATReq = 
          GoogleOAuthAccessTokenRequest
            { _grant_type = grantType
            , _assertion = jwt
            }
    return (toJSON googleOAuthATReq)

callFetchTokenAPI :: Manager -> Int -> Text -> Text -> Text -> Text -> String -> Text -> String -> IO Text
callFetchTokenAPI manager tokenExpiry issuer subject audience scope filePath grantType googleOAuthTokenUrl = do
    req <- createGoogleOAuthATReq tokenExpiry issuer subject audience scope filePath grantType
    initialRequest <- parseRequest googleOAuthTokenUrl
    let googleOAuthATReq = initialRequest { method = "POST", requestBody = RequestBodyLBS $ A.encode req , requestHeaders = [(hContentType, "application/json")]}
    responseOauth <- httpLbs googleOAuthATReq manager
    let resBody =  A.eitherDecode (responseBody responseOauth) :: Either String GoogleOAuthAccessTokenResponse
    case resBody of
        Left err -> throwIO (GoogleOAuthException err)
        Right (GoogleOAuthAccessTokenSuccessResponse accessToken _ _ _) -> return accessToken
        Right (GoogleOAuthAccessTokenFailureResponse err _) -> throwIO (GoogleOAuthException $ unpack err)

callAPIWithExceptionHandling :: Manager -> Int -> Text -> Text -> Text -> Text -> String -> Text -> String -> IO (Either SomeException Text)
callAPIWithExceptionHandling  manager tokenExpiry issuer subject audience scope filePath grantType googleOAuthTokenUrl = 
  try $ callFetchTokenAPI manager tokenExpiry issuer subject audience scope filePath grantType googleOAuthTokenUrl

fetchAndUpdateRedisAuthToken :: IORef Text -> Manager -> IO ()
fetchAndUpdateRedisAuthToken ref manager = do
    authTokenFetchInterval <- fromMaybe 500000 . (>>= readMaybe) <$> lookupEnv "AUTHTOKEN_FETCH_INTERVAL"
    (tokenExpiry, issuer, subject, audience, scope, filePath, grantType, googleOAuthTokenUrl) <- getGoogleOauthConfigs
    forever $ do
        authToken <- callAPIWithExceptionHandling manager tokenExpiry issuer subject audience scope filePath grantType googleOAuthTokenUrl
        case authToken of
            Right authToken' -> writeIORef ref authToken'
            Left ex -> putStrLn $ "Caught exception in fetchAndUpdateRedisAuthToken: " ++ show ex
        threadDelay authTokenFetchInterval

getGoogleOauthConfigs :: IO (Int, Text, Text, Text, Text, String, Text, String)
getGoogleOauthConfigs = do
  tokenExpiry <- fromMaybe 45 . (>>= readMaybe) <$> lookupEnv "GOOGLE_OAUTH_TOKEN_EXPIRY"
  issuer <- T.pack . fromMaybe "upi-callbacks@jp-dev-chaos.iam.gserviceaccount.com"  <$> lookupEnv "GOOGLE_OAUTH_ISSUER"
  subject <- T.pack . fromMaybe "upi-callbacks@jp-dev-chaos.iam.gserviceaccount.com" <$> lookupEnv "GOOGLE_OAUTH_SUBJECT"
  audience <- T.pack . fromMaybe "https://oauth2.googleapis.com/token" <$> lookupEnv "GOOGLE_OAUTH_AUDIENCE"
  scope <- T.pack . fromMaybe "https://www.googleapis.com/auth/nbupayments" <$> lookupEnv "GOOGLE_OAUTH_SCOPE"
  filePath <- join $ fromJustErr "Env GOOGLE_OAUTH_PRIVATE_KEY is not set though dynamic auth is required"  <$> (lookupEnv "GOOGLE_OAUTH_PRIVATE_KEY")
  grantType <- T.pack . fromMaybe "urn:ietf:params:oauth:grant-type:jwt-bearer" <$> lookupEnv "GOOGLE_OAUTH_GRANT_TYPE"
  googleOAuthTokenUrl <- fromMaybe "https://oauth2.googleapis.com/token" <$> lookupEnv "GOOGLE_OAUTH_TOKEN_URL"
  return (tokenExpiry, issuer, subject, audience, scope, filePath, grantType, googleOAuthTokenUrl)
