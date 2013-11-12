{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}

-- |
-- Module      : Network.HTTP.Conduit.OAuth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
--
-- This module exposes the simplest API for *accessing* OAuth
-- resources. Importantly, credential *generation* is outside the
-- scope of this API and it's assumed you have 'Token' level
-- credentials.

module Network.HTTP.Conduit.OAuth -- (
  -- -- $oauth

  -- -- * Basic
  -- module Network.HTTP.Conduit.OAuth.Types,

  -- -- * Three Legged Flow
  -- getTempCreds, getTok, buildAuthorizationRequest

  -- )
       where

import qualified Control.Exception                            as E
import qualified Control.Exception.Lifted                     as EL
import           Control.Monad.Identity
import           Control.Monad.Morph
import           Control.Monad.Reader
import           Control.Monad.Trans.Resource
import qualified Data.ByteString                              as S
import qualified Data.ByteString.Lazy                         as SL
import           Data.Monoid
import qualified Network.HTTP.Conduit                         as Client
import qualified Network.HTTP.Types.URI                       as HTTP

import           Control.Applicative
import qualified Network.HTTP.Conduit.OAuth.Internal.Signing  as S
import           Network.HTTP.Conduit.OAuth.Types
import           Network.HTTP.Conduit.OAuth.Types.Credentials
import           Network.HTTP.Conduit.OAuth.Types.Params
import           Network.HTTP.Conduit.OAuth.Types.Server
import           Network.HTTP.Conduit.OAuth.Util

{- $oauth

/OAuth/

OAuth is a format for managing access tokens which mediate
authenticated and authorized data transfer between three parties:

* The client (a.k.a. consumer)

* The server (a.k.a. service provider)

* The user   (a.k.a. the resource owner)

The client wants to access resources the user controls available on
the server. The client registers as a data client with the server
receiving client credentials. Then, it requests temporary credentials
specific to a particular kind of user resource desired from the
server. These credentials are used to construct an authorization
request to the user who, approving it, generates token credentials for
the client. These token credentials allow the client to freely access
the user's resource at a later date.

/Credential Generation/

Client Credentials are provided by the server. For the purposes of
this library, they are provided externally.

Temporary Credentials are provided to the client from the server via
an HTTP request based on the Client Credentials and other data unique
to the particular kind of access the client is requesting from the
user.

-}

data OAuthConfig ty =
  OAuthConfig { _creds   :: Credentials ty
              , _serv    :: Server
              , _manager :: Client.Manager
              }
creds
  :: Functor f =>
     (Credentials ty -> f (Credentials ty'))
     -> OAuthConfig ty -> f (OAuthConfig ty')
creds inj oac   = (\x -> oac { _creds = x })   <$> inj (_creds oac)

serv
  :: Functor f =>
     (Server -> f Server) -> OAuthConfig ty -> f (OAuthConfig ty)
serv inj oac    = (\x -> oac { _serv = x })    <$> inj (_serv oac)

manager
  :: Functor f =>
     (Client.Manager -> f Client.Manager)
     -> OAuthConfig ty -> f (OAuthConfig ty)
manager inj oac = (\x -> oac { _manager = x }) <$> inj (_manager oac)

newtype OAuthT ty m a =
  OAuthT (
    ReaderT (OAuthConfig ty) (ResourceT m) a
    )
  deriving ( Functor, Applicative,
             Monad, MonadReader (OAuthConfig ty), MonadIO )

-- | 'OAuthT' defaulted to use 'IO' as the base monad.
type  OAuth ty = OAuthT ty IO

runOAuthT :: ( MonadUnsafeIO m, MonadThrow m
             , MonadIO m, MonadBaseControl IO m
             ) =>
             Credentials ty -> Server -> OAuthT ty m a -> m a
runOAuthT c s (OAuthT o) = Client.withManager $ \m ->
  runReaderT o (OAuthConfig c s m)

runOAuth :: Credentials ty -> Server -> OAuth ty a -> IO a
runOAuth = runOAuthT

-- | Given a way to upgrade 'Credentials', run an inner 'OAuth' action
-- with such elevated 'Credentials'.
withCreds :: Monad m =>
             (Credentials ty -> Credentials ty') ->
             OAuthT ty' m a -> OAuthT ty m a
withCreds upgrade (OAuthT o) = do
  state <- ask
  OAuthT $ lift $ runReaderT o (over creds upgrade state)


instance MonadTrans (OAuthT ty) where
  lift = OAuthT . lift . lift

-- | Lift an 'Identity'-monad 'Client.Request' into any other monad.
freeRequest :: Monad m => Client.Request Identity -> Client.Request m
freeRequest req = req {
  Client.requestBody = case Client.requestBody req of
     Client.RequestBodyLBS lbs     -> Client.RequestBodyLBS lbs
     Client.RequestBodyBS   bs     -> Client.RequestBodyBS   bs
     Client.RequestBodyBuilder i b -> Client.RequestBodyBuilder i b
     Client.RequestBodySource i c  ->
       Client.RequestBodySource i (hoist (return . runIdentity) c)
     Client.RequestBodySourceChunked c ->
       Client.RequestBodySourceChunked (hoist (return . runIdentity) c)
  }

note :: String -> Maybe a -> Either String a
note s Nothing  = Left s
note _ (Just a) = Right a

newOa :: MonadIO m => OAuthT ty m (Oa ty)
newOa = do
  c <- view creds
  s <- view serv
  liftIO $ freshOa c s Nothing

-- | Try to send a signed 'Request'. This is a complex interface which
-- demands a lot from the base monad of 'OAuthT'. For most users,
-- 'send' is recommended.
sendT
  :: (MonadUnsafeIO m, MonadThrow m, MonadIO m,
      MonadBaseControl IO m, EL.Exception e) =>
     Oa ty -> Request -> OAuthT ty m (Either e (Client.Response SL.ByteString))
sendT oax req = do
  c <- view creds
  s <- view serv
  let signedReq = freeRequest (S.sign c s oax req)
  m <- view manager
  OAuthT . lift . EL.try $ Client.httpLbs signedReq m

-- | Try to send a signed 'Request'.
send :: Oa ty -> Request -> OAuth ty (Either Client.HttpException (Client.Response SL.ByteString))
send = send

getTempCreds' :: ThreeLeggedFlow ->
                 OAuth Client (Either String (Credentials Temporary))
getTempCreds' tlf = do
  oax <- newOa <&> set (oaCallback . _Just) (view callback tlf)
  eitRes <- send oax (view temporaryCredentialRequest tlf)
  c <- view creds
  return $ do
    resp <- either (Left . show) Right eitRes
    let qs = HTTP.parseQuery . SL.toStrict . Client.responseBody $ resp
    oaTok <- note "Bad credential response: missing oauth_token"
             $ join (lookup "oauth_token"        qs)
    oaSec <- note "Bad credential response: missing oauth_token_secret"
             $ join (lookup "oauth_token_secret" qs)
    return (temporaryCredentials (Token oaTok oaSec) c)


getTempCreds :: Credentials Client -> Callback -> Server -> ThreeLeggedFlow
                -> IO (Either String (Credentials Temporary))
getTempCreds cred cb srv tlf = do
  oax <- freshOa cred srv (Just cb)
  let req = S.sign cred srv oax (view temporaryCredentialRequest tlf)
  tryResp <- E.try (Client.withManager $ Client.httpLbs $ freeRequest req)
  return $ case tryResp of
    Left e     -> Left $ show (e :: E.SomeException)
    Right resp -> do
      let qs = HTTP.parseQuery . SL.toStrict . Client.responseBody $ resp
      oaTok <- note "Bad credential response: missing oauth_token"
               $ join (lookup "oauth_token"        qs)
      oaSec <- note "Bad credential response: missing oauth_token_secret"
               $ join (lookup "oauth_token_secret" qs)
      return (temporaryCredentials (Token oaTok oaSec) cred)

getTok :: Credentials Temporary -> Server -> ThreeLeggedFlow -> S.ByteString
          -> IO (Either String (Credentials Permanent))
getTok cred srv tlf verifier = do
  let req0 = view tokenRequest tlf
  oax0 <- freshOa cred srv Nothing
  let oax = set (oaVerifier . _Just) verifier oax0
  let req = S.sign cred srv oax req0
  tryResp <- E.try (Client.withManager $ Client.httpLbs $ freeRequest req)
  return $ case tryResp of
    Left e     -> Left $ show (e :: E.SomeException)
    Right resp -> do
      let qs = HTTP.parseQuery $ SL.toStrict $ Client.responseBody resp
      oaTok <- note "Bad credential response: missing oauth_token"
               $ join (lookup "oauth_token"        qs)
      oaSec <- note "Bad credential response: missing oauth_token_secret"
               $ join (lookup "oauth_token_secret" qs)
      return (permanentCredentials (Token oaTok oaSec) cred)

buildAuthorizationRequest
  :: Credentials Temporary -> ThreeLeggedFlow -> Client.Request Identity
buildAuthorizationRequest cs tlf =
  (view resourceOwnerAuthorize tlf) {
    Client.queryString = "?oauth_token=" <> view tokenKey cs
  }
