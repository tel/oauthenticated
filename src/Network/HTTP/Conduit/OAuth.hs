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
-- This module exposes a simple monadic API for /accessing/ OAuth
-- resources given credentials. It also exposes a few actions to
-- simplify handling the 'ThreeLeggedFlow' protocol used for
-- /requesting/ OAuth credentials.

module Network.HTTP.Conduit.OAuth (

  request, simpleRequest,

  -- * Basics

  -- $oauth_basics

  OAuth, runOAuth, withCreds, newOa, send,
  module Network.HTTP.Conduit.OAuth.Types,

  -- ** Transformer versions

  -- These have much more complex types, but allow for 'OAuthT' to be
  -- used as something other than the base transformer.
  OAuthT, runOAuthT, sendT,

  -- * Three Legged Flow

  -- $three_legged_flow

  requestPermanentCredentials,
  requestTemporaryCredentials,
  buildAuthorizationRequest

  ) where

import qualified Control.Exception                            as E
import           Control.Monad.Identity
import           Control.Monad.Morph
import           Control.Monad.Reader
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

{- $oauth_basics

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
-}

{- $three_legged_flow

/Three-Legged Flow/

In OAuth 1.0 the "three-legged flow" mechanism allows a client to
request access to a user's protected resources with the server acting
as an intermediary. Unsurprisingly, it happens in three steps.

1. Using 'Client' 'Credentials' specific to a particular client, the
client requests from the server a 'Temporary' 'Token' for use in the
remaining two steps. The 'Token' along with the 'Client' 'Credentials'
form 'Temporary' 'Credentials'.

2. The client provides the 'Temporary' 'Token' 'tokenSecret' to the
user which they provide to the server along with suitable identifying
information in order to authorize the 'Temporary' 'Credentials' to
request a 'Permanent' 'Token'. The server provides the user an OAuth
/verifier/ code.

3. The user returns the verifier code to the client which it uses
along with the 'Temporary' 'Credentials' from before to construct a
'Permanent' 'Token' request to the server. If granted, this
'Permanent' 'Token' can be used to build 'Permanent' 'Credentials'
which are used from then on to access OAuth protected server resources
on behalf of the user.

The final details for the three-legged flow is in how the client and
server determine how the user will authorize requests and provide the
verifier back to the client. During the first step the client must
also provide a 'Callback' as part of the 'Temporary' 'Token'
request. This callback specifies either that the verifier handoff will
occur 'OutOfBand' or via a particular 'Callback' 'Request'. If it's
the later then the server will put in a POST request to the 'Callback'
URI containing the @oauth_verifier@.

-}

-- | Configuration information for running OAuth. Not exported.
data OAuthConfig ty =
  OAuthConfig { _creds :: Credentials ty
              , _serv  :: Server
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

-- | An OAuth 'Monad' transformer. This holds information about the
-- current credentials and server configuration along with resources
-- needed to perform HTTP requests.
newtype OAuthT ty m a =
  OAuthT (
    ReaderT (OAuthConfig ty) m a
    )
  deriving ( Functor, Applicative,
             Monad, MonadReader (OAuthConfig ty), MonadIO )

instance MonadTrans (OAuthT ty) where
  lift = OAuthT . lift

-- | 'OAuthT' with 'IO' as the base monad. This is the preferred monad
-- for using OAuth.
type OAuth ty = OAuthT ty IO

-- | Execute an 'OAuthT' monad with the proper 'Credentials' and
-- 'Server' information. This has a sophisticated type and is only
-- useful when it's desirable to have a different monad than 'OAuth'
-- as your base monad. In most cases, this should be avoided.
runOAuthT :: Credentials t -> Server -> OAuthT t m a -> m a
runOAuthT c s (OAuthT o) = runReaderT o (OAuthConfig c s)

-- | Streamlined API for requesting resources using 'Permanent'
-- 'Credentials'. This provides a similar interface as
-- 'Client.simpleHttp', but is more efficient since it will re-use the
-- 'Manager' within the 'OAuth' monad.
simpleRequest :: String ->
                 OAuth Permanent (Either Client.HttpException
                                         (Client.Response SL.ByteString))
simpleRequest = Client.parseUrl >=> request

-- | Streamlined API for requesting resource using 'Permanent'
-- 'Credentials'. This provides a similar api as 'simpleRequest' but
-- requires the 'Request' be generated separately.
request :: Request ->
           OAuth Permanent (Either Client.HttpException
                            (Client.Response SL.ByteString))
request req = newOa >>= flip send req

-- | Execute an 'OAuth' monad with the proper 'Credentials' and
-- 'Server' information. This generates a new 'Client.Manager' which
-- is used for the entirety of the 'OAuth' monad's execution.
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

-- | Lift an 'Identity'-monad 'Client.Request' into any other
-- monad. Useful because generally @http-conduit@ requires
-- polymorphism in its 'Client.Request' monad, but we need that monad
-- to be 'Identity' in order to compute OAuth signing parameters.
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

-- | Produce a new 'Oa' parameter bundle. This will be valid for a
-- short period of time, but can be \"refreshed\" by using @liftIO
-- . refreshOa@.
newOa :: MonadIO m => OAuthT ty m (Oa ty)
newOa = do
  c <- view creds
  s <- view serv
  liftIO $ freshOa c s Nothing

-- | Try to sign and send a 'Request' using some particular 'Oa'
-- parameter bundle. This is a complex interface which demands a lot
-- from the base monad of 'OAuthT'. For most users, 'send' is
-- recommended.
sendT
  :: (MonadIO m, E.Exception e) =>
     Oa ty -> Request -> OAuthT ty m (Either e (Client.Response SL.ByteString))
sendT oax req = do
  c <- view creds
  s <- view serv
  let signedReq = freeRequest (S.sign c s oax req)
  liftIO . E.try $ Client.withManager (Client.httpLbs signedReq)

-- | Try to sign and send a 'Request' using some particular 'Oa'
-- parameter bundle.
send :: Oa ty -> Request -> OAuth ty (Either Client.HttpException (Client.Response SL.ByteString))
send = sendT

lookupOrComplain :: S.ByteString -> HTTP.Query -> Either String S.ByteString
lookupOrComplain name qs = case lookup name qs of
  Nothing       -> Left $ "Bad credential response: missing " ++ show name
  Just Nothing  -> Left $ "Bad credential response: missing " ++ show name
  Just (Just s) -> Right s

fmapL :: (e -> e') -> Either e a -> Either e' a
fmapL f (Left e) = Left (f e)
fmapL _ (Right a) = Right a

-- | Using 'Client' 'Credentials', request 'Temporary' 'Credentials'
-- via the first leg of a given 'ThreeLeggedFlow'.
requestTemporaryCredentials
  :: ThreeLeggedFlow -> OAuth Client (Either String (Credentials Temporary))
requestTemporaryCredentials tlf = do
  oax <- newOa <&> set (oaCallback . _Just) (view callback tlf)
  eitRes <- send oax (view temporaryCredentialRequest tlf)
  c <- view creds
  return $ do
    resp <- fmapL show eitRes
    let qs = HTTP.parseQuery . SL.toStrict . Client.responseBody $ resp
    tok <- Token <$> lookupOrComplain "oauth_token" qs
                 <*> lookupOrComplain "oauth_token_secret" qs
    return (temporaryCredentials tok c)

-- | Using 'Temporary' 'Credentials', request 'Permanent'
-- 'Credentials' using a verifier 'S.ByteString' via the final leg of
-- a given 'ThreeLeggedFlow'.
requestPermanentCredentials
  :: ThreeLeggedFlow -> S.ByteString -> OAuth Temporary (Either String (Credentials Permanent))
requestPermanentCredentials tlf verifier = do
  oax <- newOa <&> set (oaVerifier . _Just) verifier
  eitRes <- send oax (view temporaryCredentialRequest tlf)
  c <- view creds
  return $ do
    resp <- fmapL show eitRes
    let qs = HTTP.parseQuery . SL.toStrict . Client.responseBody $ resp
    tok <- Token <$> lookupOrComplain "oauth_token" qs
                 <*> lookupOrComplain "oauth_token_secret" qs
    return (permanentCredentials tok c)

-- | Using 'Temporary' 'Credentials' build a 'Request' suitable for a
-- /user/ to use in order to authorize the 'Temporary' 'Credentials'
-- for 'requestPermanentCredentials'.
buildAuthorizationRequest
  :: ThreeLeggedFlow -> OAuth Temporary Request
buildAuthorizationRequest tlf = do
  let req0 = view resourceOwnerAuthorize tlf
  tok <- view (creds . tokenKey)
  return req0 {
    Client.queryString = "?oauth_token=" <> tok
  }
