{-# LANGUAGE TupleSections #-}

-- |
-- Module      : Network.OAuth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- "Network.OAuth" provides simple OAuth signed requests atop
-- "Network.HTTP.Client". This module exports a simplified interface atop
-- the monadic interface defined in "Network.OAuth.Stateful".
--
-- If more control is needed, the low-level functions for creating, customizing,
-- and managing OAuth 'Cred'entials, 'Token's, and parameter sets ('Oa')
-- are using them to sign 'Network.HTTP.Client.Types.Request's are
-- available in "Network.OAuth.Types.Params",
-- "Network.OAuth.Types.Credentials", and "Network.OAuth.Signing".

module Network.OAuth (

  -- * The basic monadic API
  oauth,

  -- * Simplified requests layer
  simpleOAuth, Params (..), Query, QueryItem,

  -- * OAuth Monad
  --
  -- The 'OAuthT' monad is nothing more than a 'Control.Monad.State.StateT'
  -- transformer containing OAuth state.
  OAuthT, runOAuthT, runOAuthT',

  -- * OAuth Configuration
  --
  -- OAuth requests are parameterized by 'Server' configuration and client
  -- 'Cred'entials. These can be modified within an 'OAuthT' thread by using
  -- the 'Network.OAuth.MuLens.Lens'es in "Network.OAuth.Stateful".
  Server (..), ParameterMethod (..), SignatureMethod (..), Version (..),
  defaultServer,

  -- ** Credential managerment
  --
  -- Credentials are parameterized by 3 types
  Permanent, Temporary, Client,

  -- And are composed of both 'Token's and 'Cred'entials.
  Cred, Token (..),
  clientCred, temporaryCred, permanentCred,

  -- ** Access lenses
  key, secret, clientToken, resourceToken
  ) where

import           Control.Applicative
import           Control.Monad.Catch
import           Control.Monad.Trans
import qualified Data.ByteString.Lazy            as SL
import           Data.Maybe                      (mapMaybe)
import           Network.HTTP.Client             (httpLbs)
import           Network.HTTP.Client.Request     (parseUrl, urlEncodedBody)
import           Network.HTTP.Client.Response    (Response)
import           Network.HTTP.Client.Types       (HttpException, method,
                                                  queryString)
import           Network.HTTP.Types              (Query, QueryItem, methodGet,
                                                  renderQuery)
import           Network.OAuth.Stateful
import           Network.OAuth.Types.Credentials (Client, Cred, Permanent,
                                                  Temporary, Token (..),
                                                  clientCred, clientToken, key,
                                                  permanentCred, resourceToken,
                                                  secret, temporaryCred)
import           Network.OAuth.Types.Params      (ParameterMethod (..),
                                                  Server (..),
                                                  SignatureMethod (..),
                                                  Version (..), defaultServer)

-- | 'Params' quickly set the parameterization of a 'Request', either
-- a @GET@ request with a query string or a @POST@ request with
-- a @www-form-urlencoded@ body.
data Params = QueryParams Query
            | BodyParams  Query

-- | Send an OAuth GET request to a particular URI. Throws an exception if
-- the URI cannot be parsed or if errors occur during the request.
simpleOAuth
  :: (MonadIO m, MonadCatch m) =>
  String -> Params -> OAuthT ty m (Response SL.ByteString)
simpleOAuth url ps = case parseUrl url of
  Left err -> lift $ throwM (err :: HttpException)
  Right rq -> do
    signedRq <- oauth $ addParams ps rq
    withManager (liftIO . httpLbs signedRq)
  where
    addParams (QueryParams q) req =
      req { method = methodGet
          , queryString = renderQuery True q
          }
    addParams (BodyParams q) req =
      let params = mapMaybe (\(a, b) -> (a,) <$> b) q
      in  urlEncodedBody params req
