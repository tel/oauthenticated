{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- |
-- Module      : Network.HTTP.Conduit.OAuth.Types.Server
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- /Server Configuration/
--
-- Each server needs to be properly specified in order to create a
-- compliant request for it.

module Network.HTTP.Conduit.OAuth.Types.Server (

  -- * Base server type
  Server (..), ThreeLeggedFlow (..), parseThreeLeggedFlow,

  -- * Lenses

  -- ** Server
  threeLeggedFlow, parameterMethod, signatureMethod, oauthVersion,

  -- ** ThreeLeggedFlow
  temporaryCredentialRequest, resourceOwnerAuthorize, tokenRequest,
  getTemporaryCredentialRequest, getResourceOwnerAuthorize, getTokenRequest,

  ) where

import           Control.Applicative
import           Control.Failure
import           Control.Monad
import qualified Network.HTTP.Conduit                   as Client
import           Network.HTTP.Conduit.OAuth.Types.Basic
import           Network.HTTP.Conduit.OAuth.Util

-- | The 'ThreeLeggedFlow' configures endpoints at a 'Server'
-- responsible for handling temporary credential requests, client
-- authorization requests, and permanent token upgrade requests.
data ThreeLeggedFlow = ThreeLeggedFlow
                       Request
                       -- ^ Base request for requesting 'Temporary'
                       -- 'Credentials'. This includes both the URI,
                       -- the HTTP method, and whether or not it
                       -- should be a secure request.
                       Request
                       -- ^ Base request for authorizing 'Temporary'
                       -- 'Credentials'. This is passed to the user
                       -- for them to use to provide authorization to
                       -- the server.
                       Request
                       -- ^ Base request for requesting 'Token'
                       -- 'Credentials' using authorized 'Temporary'
                       -- 'Credentials'.
                     deriving ( Show )

temporaryCredentialRequest, resourceOwnerAuthorize, tokenRequest
  :: Functor f =>
    (Request -> f Request) -> ThreeLeggedFlow -> f ThreeLeggedFlow

temporaryCredentialRequest inj (ThreeLeggedFlow a b c) =
  (\a' -> ThreeLeggedFlow a' b c) <$> inj a
{-# INLINE temporaryCredentialRequest #-}

resourceOwnerAuthorize inj (ThreeLeggedFlow a b c) =
  (\b' -> ThreeLeggedFlow a b' c) <$> inj b
{-# INLINE resourceOwnerAuthorize #-}

tokenRequest inj (ThreeLeggedFlow a b c) =
  (\c' -> ThreeLeggedFlow a b c') <$> inj c
{-# INLINE tokenRequest #-}

getTemporaryCredentialRequest, getResourceOwnerAuthorize, getTokenRequest
  :: ThreeLeggedFlow -> Request

getTemporaryCredentialRequest = view temporaryCredentialRequest
getResourceOwnerAuthorize     = view resourceOwnerAuthorize
getTokenRequest               = view tokenRequest

-- | The 'Server' denotes the OAuth configuration specific to a
-- particular server.
data Server = Server
              (Maybe ThreeLeggedFlow)
              ParameterMethod
              -- ^ The server's preferred @oauth_*@ parameter passing
              -- method. The OAuth standard prefers the
              -- @Authorization:@ header, but allows for parameters to
              -- be passed in the entity body or the query string as
              -- well.
              SignatureMethod
              -- ^ The server's preferred signature method used for
              -- signing OAuth requests.
              Version
              -- ^ The server's implemented OAuth version. This should
              -- be chosen to be the latest OAuth version the server
              -- is compliant with.
            deriving ( Show )

-- | Lens on the 3-legged flow of a server.
threeLeggedFlow
  :: Functor f => (Maybe ThreeLeggedFlow -> f (Maybe ThreeLeggedFlow)) -> Server -> f Server
threeLeggedFlow inj (Server tlf p s v) =
  (\tlf' -> Server tlf' p s v) <$> inj tlf
{-# INLINE threeLeggedFlow #-}

parameterMethod
  :: Functor f => (ParameterMethod -> f ParameterMethod) -> Server -> f Server
parameterMethod inj (Server tlf p s v) =
  (\p' -> Server tlf p' s v) <$> inj p
{-# INLINE parameterMethod #-}

signatureMethod
  :: Functor f => (SignatureMethod -> f SignatureMethod) -> Server -> f Server
signatureMethod inj (Server tlf p s v) =
  (\s' -> Server tlf p s' v) <$> inj s
{-# INLINE signatureMethod #-}

oauthVersion
  :: Functor f => (Version -> f Version) -> Server -> f Server
oauthVersion inj (Server tlf p s v) = Server tlf p s <$> inj v
{-# INLINE oauthVersion #-}

parseThreeLeggedFlow :: Failure Client.HttpException m
                        => String -> String -> String
                        -> m ThreeLeggedFlow
parseThreeLeggedFlow tcr ror tr
  = ThreeLeggedFlow
    `liftM` Client.parseUrl tcr
    `ap`    Client.parseUrl ror
    `ap`    Client.parseUrl tr
