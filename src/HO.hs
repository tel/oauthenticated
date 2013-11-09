{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}

module HO where

{- OAuth
--------------------------------------------------------------------------------
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

Credential Generation
--------------------------------------------------------------------------------
Client Credentials are provided by the server. For the purposes of
this library, they are provided externally.

Temporary Credentials are provided to the client from the server via
an HTTP request based on the Client Credentials and other data unique
to the particular kind of access the client is requesting from the
user.

-}

import qualified Control.Exception      as E
import           Control.Monad.Identity
import           Control.Monad.Morph
import qualified Data.ByteString.Lazy   as SL
import qualified Network.HTTP.Conduit   as Client
import qualified Network.HTTP.Types.URI as HTTP

import           Signing
import           Types

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

getTempCreds :: Credentials Client -> Server -> IO (Maybe (Credentials Temporary))
getTempCreds cred srv = do
  req <- freeze cred srv (temporaryCredentialRequest srv)
  print req
  tryResp <- E.try (Client.withManager $ Client.httpLbs $ freeRequest req)
  case tryResp of
    Left e     -> print (e :: E.SomeException) >> return Nothing
    Right resp -> return $ do
      let qs = HTTP.parseQuery $ SL.toStrict $ Client.responseBody resp
      oaTok <- join (lookup "oauth_token"        qs)
      oaSec <- join (lookup "oauth_token_secret" qs)
      return (createTemporaryCredentials oaTok oaSec cred)
