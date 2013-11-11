{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE PolyKinds             #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE StandaloneDeriving    #-}

module Network.HTTP.Conduit.OAuth.Types where

import           Control.Applicative
import           Control.Arrow
import           Control.Failure
import           Control.Monad
import           Control.Monad.Identity
import qualified Data.ByteString                            as S
import qualified Data.ByteString.Base16                     as S16
import qualified Data.ByteString.Char8                      as S8
import qualified Data.CaseInsensitive                       as CI
import           Data.Maybe
import           Data.Monoid
import           Data.Time
import qualified Network.HTTP.Conduit                       as Client
import qualified Network.HTTP.Conduit.Internal              as Client
import           Network.HTTP.Conduit.OAuth.Internal.ToHTTP
import qualified Network.HTTP.Types                         as HTTP
import           System.Random

-- Credentials
--------------------------------------------------------------------------------

-- Credentials are created at various points during the OAuth
-- handshakes. Each time they are a pair of a key and a secret, the
-- first of which being public the second private.

data CredentialType = Client | Temporary | Token
                    deriving ( Show, Eq, Ord )

data Credentials :: CredentialType -> * where
  ClientCredentials
    :: S.ByteString -> S.ByteString -> Callback -> Credentials Client
       -- ^ Client Credentials are linked to a particular callback url.
  TemporaryCredentials
    :: S.ByteString -> S.ByteString    -- linked client credentials
       -> S.ByteString -> S.ByteString -- temporary credentials
       -> Credentials Temporary
  TokenCredentials
    :: S.ByteString -> S.ByteString    -- linked client credentials
       -> S.ByteString -> S.ByteString -- temporary credentials
       -> Credentials Token

credCallback :: Credentials Client -> Callback
credCallback (ClientCredentials _ _ cb) = cb

credCallback' :: Credentials ty -> Maybe Callback
credCallback' (ClientCredentials _ _ cb    ) = Just cb
credCallback' _                              = Nothing

credClientKey :: Credentials ty -> S.ByteString
credClientKey (ClientCredentials    k _ _    ) = k
credClientKey (TemporaryCredentials k _ _ _  ) = k
credClientKey (TokenCredentials     k _ _ _  ) = k

credClientSecret :: Credentials ty -> S.ByteString
credClientSecret (ClientCredentials    _ s _    ) = s
credClientSecret (TemporaryCredentials _ s _ _  ) = s
credClientSecret (TokenCredentials     _ s _ _  ) = s

credToken :: Credentials ty -> S.ByteString
credToken (ClientCredentials    _ _ _    ) = ""
credToken (TemporaryCredentials _ _ t _  ) = t
credToken (TokenCredentials     _ _ t _  ) = t

credTokenSecret :: Credentials ty -> S.ByteString
credTokenSecret (ClientCredentials    _ _ _    ) = ""
credTokenSecret (TemporaryCredentials _ _ _ s  ) = s
credTokenSecret (TokenCredentials     _ _ _ s  ) = s

-- | Creates a signing key based on the kind of credentials currently
-- possessed.
credSigningKey :: Credentials ty -> S.ByteString
credSigningKey cred =
  HTTP.urlEncode True (credClientSecret cred)
  <> "&" <>
  HTTP.urlEncode True (credTokenSecret cred)

credType :: Credentials ty -> CredentialType
credType ClientCredentials{}    = Client
credType TemporaryCredentials{} = Temporary
credType TokenCredentials{}     = Token

createTemporaryCredentials
  :: S.ByteString -> S.ByteString
     -> Credentials Client -> Credentials Temporary
createTemporaryCredentials tok tokSec (ClientCredentials k s _) =
  TemporaryCredentials k s tok tokSec

createTokenCredentials
  :: S.ByteString -> S.ByteString
     -> Credentials Temporary -> Credentials Token
createTokenCredentials tok tokSec (TemporaryCredentials k s _ _) =
  TokenCredentials k s tok tokSec

instance Show (Credentials Client) where
  show c = "Credentials [Client] { credClientKey = "
           ++ show (credClientKey c)
           ++ " }"

instance Show (Credentials Temporary) where
  show (TemporaryCredentials ck _ tk _) =
    "Credentials [Temporary] { credClientKey = "
    ++ show ck
    ++ ", temporaryKey = "
    ++ show tk
    ++ " }"

instance Show (Credentials Token) where
  show (TokenCredentials ck _ tk _) =
    "Credentials [Token] { credClientKey = "
    ++ show ck
    ++ ", tokenKey = "
    ++ show tk
    ++ " }"


-- | Clients MUST provide callback URLs to the Server or the string
-- \"oob\" indicating out-of-band authorization will occur.
data Callback = Callback (Client.Request IO) | OutOfBand
                deriving ( Show )

instance ToHTTP Callback where
  toHTTP (Callback req) = HTTP.urlEncode True . S8.pack . show . Client.getUri $ req
  toHTTP OutOfBand      = "oob"

instance FromHTTP Callback where
  fromHTTP s = case CI.mk s of
    ci | ci == "oob" -> Just OutOfBand
       | otherwise   -> Callback <$> Client.parseUrl (S8.unpack s)

-- | Tries to create a 'Callback' from a 'String' representation. This
-- can fail if the 'String' is not a proper URL.
parseCallback :: String -> Maybe Callback
parseCallback = liftM Callback . Client.parseUrl

-- Server Configuration
--------------------------------------------------------------------------------

-- Each server needs to be properly specified in order to create a
-- compliant request for it.

-- | The 'Server' denotes the OAuth configuration specific to a
-- particular server.
data Server =
  Server { temporaryCredentialRequest :: Client.Request Identity
           -- ^ Base request for requesting 'Temporary'
           -- 'Credentials'. This includes both the URI, the HTTP
           -- method, and whether or not it should be a secure
           -- request.
         , resourceOwnerAuthorize     :: Client.Request Identity
           -- ^ Base request for authorizing 'Temporary'
           -- 'Credentials'. This is passed to the user for them to
           -- use to provide authorization to the server.
         , tokenRequest               :: Client.Request Identity
           -- ^ Base request for requesting 'Token' 'Credentials'
           -- using authorized 'Temporary' 'Credentials'.
         , parameterMethod            :: ParameterMethod
           -- ^ The server's preferred @oauth_*@ parameter passing method. The
           -- OAuth standard prefers the @Authorization:@ header, but
           -- allows for parameters to be passed in the entity body or
           -- the query string as well.
         , signatureMethod            :: SignatureMethod
           -- ^ The server's preferred signature method used for
           -- signing OAuth requests.
         , serverVersion              :: Version
           -- ^ The server's implemented OAuth version. This should be
           -- chosen to be the latest OAuth version the server is
           -- compliant with.
         }

instance Show Server where
  show (Server tcr ror tr pm sm ver) =
    let tcrUrl = show . Client.getUri $ tcr
        rorUrl = show . Client.getUri $ ror
        trUrl  = show . Client.getUri $ tr
    in "Server { temporaryCredentialRequest = " ++ tcrUrl
       ++ ", resourceOwnerRequest = " ++ rorUrl
       ++ ", tokenRequest = " ++ trUrl
       ++ ", parameterMethod = " ++ show pm
       ++ ", signatureMethod = " ++ show sm
       ++ ", serverVersion = " ++ show ver
       ++ " }"

parseServer :: Failure Client.HttpException m
               => String -> String -> String
               -> ParameterMethod -> SignatureMethod -> Version
               -> m Server
parseServer tcr ror tr pm sm ver
  = Server
    `liftM` (Client.parseUrl tcr)
    `ap`    (Client.parseUrl ror)
    `ap`    (Client.parseUrl tr)
    `ap`    (return pm)
    `ap`    (return sm)
    `ap`    (return ver)

-- | The OAuth spec suggest that the OAuth parameter be passed via the
-- @Authorization@ header, but allows for other methods of
-- transmission (see section "3.5. Parameter Transmission") so we
-- select the 'Server'\'s preferred method with this type.
data ParameterMethod = AuthorizationHeader
                     | RequestEntityBody
                     | QueryString
                       deriving ( Show, Eq, Ord )

-- | How the OAuth request be cryptographically signed. If 'Plaintext'
-- is used then the request should be conducted over a secure
-- transport layer like TLS.
data SignatureMethod = HmacSha1
--                     | Plaintext
                     deriving ( Show, Eq, Ord )

instance ToHTTP SignatureMethod where
--  toHTTP Plaintext = "PLAINTEXT"
  toHTTP HmacSha1  = "HMAC-SHA1"

instance FromHTTP SignatureMethod where
  fromHTTP s = case CI.mk s of
    ci | ci == "hmac-sha1" -> Just HmacSha1
--       | ci == "plaintext" -> Just Plaintext
       | otherwise         -> Nothing

data Version = OAuth10
               -- ^ Version "1.0"
             deriving ( Show, Eq, Ord )

instance ToHTTP Version where
  toHTTP OAuth10 = "1.0"

instance FromHTTP Version where
  fromHTTP "1.0" = Just OAuth10
  fromHTTP _     = Nothing

-- OAuth Parameters
--------------------------------------------------------------------------------

-- Broadly OAuth assumes there are two kinds of parameters: the
-- standard ones parsed either from a @www-form-urlencoded@-type body
-- or the querystring and the OAuth parameters themselves which may
-- eventually be encoded into the header, the body, or the querystring
-- (based on the value of 'ParameterMethod').
--
-- These are treated identically for signing purposes, but the OAuth
-- parameters can be thought of as being collected "above" the base
-- parameters and are linked to a particular OAuth request process.

data Oa ty = Oa { oaVersion         :: Version
                , oaCredentials     :: Credentials ty
                , oaToken           :: S.ByteString
                , oaSignatureMethod :: SignatureMethod

                , oaCallback        :: Maybe Callback
                  -- ^ only needed to get temporary creds
                , oaVerifier        :: Maybe S.ByteString
                  -- ^ only used to get token creds

                , oaTimestamp       :: UTCTime
                  -- ^ impurely generated per request
                , oaNonce           :: S.ByteString
                  -- ^ impurely generated per request

                , oaSignature       :: Maybe S.ByteString
                  -- ^ Generated in the final step
                }

deriving instance Show (Oa Client)
deriving instance Show (Oa Temporary)
deriving instance Show (Oa Token)

-- | Creates a pure, unsigned 'Oa'. This does not include the
-- 'oaVerifier' so those must be added manually if used.
oa :: Credentials ty -> Server -> UTCTime -> S.ByteString -> Oa ty
oa cred srv time nonce =
  Oa { oaVersion         = serverVersion srv
     , oaCredentials     = cred
     , oaToken           = credToken cred
     , oaSignatureMethod = signatureMethod srv
     , oaCallback        = credCallback' cred
     , oaVerifier        = Nothing
     , oaTimestamp       = time
     , oaNonce           = nonce
     , oaSignature       = Nothing
     }

-- | Create a \"fresh\" 'Oa' for this exact moment---automatically
-- generates the 'oaNonce' and 'oaTimestamp' components.
freshOa :: Credentials ty -> Server -> IO (Oa ty)
freshOa cred srv = oa cred srv
                   <$> getCurrentTime
                   <*> newNonce
  where newNonce = S16.encode . S.pack <$> replicateM 18 randomIO

oaDict :: Oa ty -> [(S.ByteString, S.ByteString)]
oaDict oax =
  catMaybes
  [ pair "oauth_version" . toHTTP           .$. oaVersion oax
  , pair "oauth_consumer_key"               .$. credClientKey (oaCredentials oax)
  , pair "oauth_signature_method" . toHTTP  .$. oaSignatureMethod oax
  , pair "oauth_callback" . toHTTP          <$> oaCallback oax
  , pair "oauth_verifier"                   <$> oaVerifier oax
  , pair "oauth_token"                      .$. credToken (oaCredentials oax)
  , pair "oauth_timestamp" . toHTTP         .$. oaTimestamp oax
  , pair "oauth_nonce"                      .$. oaNonce oax
  , pair "oauth_signature"                  <$> oaSignature oax
  ]
  where
    -- <$> for when your parameter is pure
    infix 8 .$.
    f .$. a = f <$> pure a
    pair :: S.ByteString -> S.ByteString -> (S.ByteString, S.ByteString)
    pair = (,)

-- | Converts an 'Oa' to @Authorization:@ header format using an
-- optional @realm@ component.
oaToHeader :: Maybe S.ByteString -> Oa ty -> S.ByteString
oaToHeader mayRealm = finish . map param . oaDict
  where
    finish params = "OAuth " <> S8.intercalate ", " (addRealm mayRealm params)
    addRealm Nothing  params = params
    addRealm (Just r) params = param ("realm", r) : params
    param :: (S.ByteString, S.ByteString) -> S.ByteString
    param (p, v) = p <> "=\"" <> v <> "\""

-- | Converts an 'Oa' to query string format.
oaToQuerystring :: Oa ty -> HTTP.Query
oaToQuerystring = map (second Just) . oaDict

-- | Converts an 'Oa' to entity body format.
oaToEntityBody :: Oa ty -> [(S.ByteString, S.ByteString)]
oaToEntityBody = oaDict
