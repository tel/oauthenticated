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
  parameterMethod, signatureMethod, oauthVersion,

  -- ** ThreeLeggedFlow
  temporaryCredentialRequest, resourceOwnerAuthorize, tokenRequest, callback,
  getTemporaryCredentialRequest, getResourceOwnerAuthorize, getTokenRequest, getCallback

  ) where

import           Control.Applicative
import           Control.Monad
import qualified Network.HTTP.Conduit                      as Client
import           Network.HTTP.Conduit.OAuth.Types.Basic
import           Network.HTTP.Conduit.OAuth.Types.Callback
import           Network.HTTP.Conduit.OAuth.Util

-- | The 'ThreeLeggedFlow' configures endpoints at a 'Server'
-- responsible for handling temporary credential requests, client
-- authorization requests, and permanent token upgrade requests.
data ThreeLeggedFlow =
  ThreeLeggedFlow {
    tlfTempCredReq       :: Request,
    -- ^ Base request for requesting 'Temporary'
    -- 'Credentials'. This includes both the URI,
    -- the HTTP method, and whether or not it
    -- should be a secure request.
    tlfResOwnerAuthorize :: Request,
    -- ^ Base request for authorizing 'Temporary'
    -- 'Credentials'. This is passed to the user
    -- for them to use to provide authorization to
    -- the server.
    tlfTokReq            :: Request,
    -- ^ Base request for requesting 'Token'
    -- 'Credentials' using authorized 'Temporary'
    -- 'Credentials'.
    tlfCallback          :: Callback
    } deriving ( Show )

temporaryCredentialRequest, resourceOwnerAuthorize, tokenRequest
  :: Functor f =>
    (Request -> f Request) -> ThreeLeggedFlow -> f ThreeLeggedFlow

temporaryCredentialRequest inj (ThreeLeggedFlow a b c cb) =
  (\a' -> ThreeLeggedFlow a' b c cb) <$> inj a
{-# INLINE temporaryCredentialRequest #-}

resourceOwnerAuthorize inj (ThreeLeggedFlow a b c cb) =
  (\b' -> ThreeLeggedFlow a b' c cb) <$> inj b
{-# INLINE resourceOwnerAuthorize #-}

tokenRequest inj (ThreeLeggedFlow a b c cb) =
  (\c' -> ThreeLeggedFlow a b c' cb) <$> inj c
{-# INLINE tokenRequest #-}

callback :: Functor f => (Callback -> f Callback) ->
            ThreeLeggedFlow -> f ThreeLeggedFlow
callback inj (ThreeLeggedFlow a b c cb) =
  ThreeLeggedFlow a b c <$> inj cb
{-# INLINE callback #-}

getTemporaryCredentialRequest, getResourceOwnerAuthorize, getTokenRequest
  :: ThreeLeggedFlow -> Request

getTemporaryCredentialRequest = view temporaryCredentialRequest
getResourceOwnerAuthorize     = view resourceOwnerAuthorize
getTokenRequest               = view tokenRequest

getCallback :: ThreeLeggedFlow -> Callback
getCallback                   = view callback

-- | The 'Server' denotes the OAuth configuration specific to a
-- particular server.
data Server = Server
              ParameterMethod
              SignatureMethod
              Version
            deriving ( Show )

parameterMethod
  :: Functor f => (ParameterMethod -> f ParameterMethod) -> Server -> f Server
parameterMethod inj (Server p s v) =
  (\p' -> Server p' s v) <$> inj p
{-# INLINE parameterMethod #-}

signatureMethod
  :: Functor f => (SignatureMethod -> f SignatureMethod) -> Server -> f Server
signatureMethod inj (Server p s v) =
  (\s' -> Server p s' v) <$> inj s
{-# INLINE signatureMethod #-}

oauthVersion
  :: Functor f => (Version -> f Version) -> Server -> f Server
oauthVersion inj (Server p s v) = Server p s <$> inj v
{-# INLINE oauthVersion #-}

parseThreeLeggedFlow :: String -> String -> String -> Callback
                        -> Either Client.HttpException ThreeLeggedFlow
parseThreeLeggedFlow tcr ror tr cb
  = ThreeLeggedFlow
    `liftM` Client.parseUrl tcr
    `ap`    Client.parseUrl ror
    `ap`    Client.parseUrl tr
    `ap`    return cb
