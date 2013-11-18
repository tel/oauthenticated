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

module Network.OAuth (
  simpleOAuth, oauth,

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

import           Control.Monad.Catch
import Control.Applicative
import           Control.Monad.Trans
import qualified Data.ByteString.Lazy            as SL
import           Data.Maybe                      (mapMaybe)
import           Network.HTTP.Client             (httpLbs)
import           Network.HTTP.Client.Request     (parseUrl, urlEncodedBody)
import           Network.HTTP.Client.Response    (Response)
import           Network.HTTP.Client.Types       (HttpException, method,
                                                  queryString)
import           Network.HTTP.Types              (Query, methodGet,
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

data Params = QueryParams Query
            | BodyParams  Query

-- | Send an OAuth GET request to a particular URI. Throws an exception if
-- the URI cannot be parsed or if errors occur during the request.
simpleOAuth
  :: (MonadCatch m, MonadIO m) =>
  String -> Params -> OAuthT Permanent m (Response SL.ByteString)
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
