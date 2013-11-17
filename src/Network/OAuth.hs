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
  oauth,

  -- * OAuth Monad
  --
  -- The 'OAuthT' monad is nothing more than a 'Control.Monad.State.StateT'
  -- transformer containing OAuth state.
  OAuthT, runOAuth, runOAuthT',

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
  Cred (..), Token (..),
  clientCred, temporaryCred, permanentCred,

  -- ** Access lenses
  key, secret, clientToken, resourceToken
  ) where

import           Network.OAuth.Stateful
import           Network.OAuth.Types.Credentials (Client, Cred (..), Permanent,
						  clientCred, temporaryCred, permanentCred,
                                                  Temporary, Token (..), clientToken,
                                                  key, resourceToken, secret)
import           Network.OAuth.Types.Params      (ParameterMethod (..),
                                                  Server (..), defaultServer,
                                                  SignatureMethod (..),
                                                  Version (..))
