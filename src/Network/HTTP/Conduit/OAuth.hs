{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}

{- |

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

module Network.HTTP.Conduit.OAuth where

import qualified Control.Exception                            as E
import           Control.Monad.Identity
import           Control.Monad.Morph
import qualified Data.ByteString                              as S
import qualified Data.ByteString.Lazy                         as SL
import           Data.Monoid
import qualified Network.HTTP.Conduit                         as Client
import qualified Network.HTTP.Types.URI                       as HTTP

import           Network.HTTP.Conduit.OAuth.Internal.Signing
import           Network.HTTP.Conduit.OAuth.Types
import           Network.HTTP.Conduit.OAuth.Types.Credentials
import           Network.HTTP.Conduit.OAuth.Types.Params
import           Network.HTTP.Conduit.OAuth.Types.Server
import           Network.HTTP.Conduit.OAuth.Util

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

getTempCreds :: Credentials Client -> Callback -> Server -> ThreeLeggedFlow
                -> IO (Either String (Credentials Temporary))
getTempCreds cred cb srv tlf = do
  oax <- freshOa cred srv (Just cb)
  let req = sign cred srv oax (view temporaryCredentialRequest tlf)
  tryResp <- E.try (Client.withManager $ Client.httpLbs $ freeRequest req)
  return $ case tryResp of
    Left e     -> Left $ show (e :: E.SomeException)
    Right resp -> do
      let qs = HTTP.parseQuery $ SL.toStrict $ Client.responseBody resp
      oaTok <- note "Bad credential response: missing oauth_token"
               $ join (lookup "oauth_token"        qs)
      oaSec <- note "Bad credential response: missing oauth_token_secret"
               $ join (lookup "oauth_token_secret" qs)
      return (temporaryCredentials (oaTok, oaSec) cred)

getTok :: Credentials Temporary -> Server -> ThreeLeggedFlow -> S.ByteString
          -> IO (Either String (Credentials Token))
getTok cred srv tlf verifier = do
  let req0 = view tokenRequest tlf
  oax0 <- freshOa cred srv Nothing
  let oax = set (oaVerifier . _Just) verifier oax0
  let req = sign cred srv oax req0
  tryResp <- E.try (Client.withManager $ Client.httpLbs $ freeRequest req)
  return $ case tryResp of
    Left e     -> Left $ show (e :: E.SomeException)
    Right resp -> do
      let qs = HTTP.parseQuery $ SL.toStrict $ Client.responseBody resp
      oaTok <- note "Bad credential response: missing oauth_token"
               $ join (lookup "oauth_token"        qs)
      oaSec <- note "Bad credential response: missing oauth_token_secret"
               $ join (lookup "oauth_token_secret" qs)
      return (tokenCredentials (oaTok, oaSec) cred)

buildAuthorizationRequest :: Credentials Temporary -> Server -> ThreeLeggedFlow
                             -> Client.Request Identity
buildAuthorizationRequest creds srv tlf =
  (view resourceOwnerAuthorize tlf) {
    Client.queryString = "?oauth_token=" <> view tokenKey creds
  }
