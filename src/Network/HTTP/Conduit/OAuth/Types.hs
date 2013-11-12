-- |
-- Module      : Network.HTTP.Conduit.OAuth.Types
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Re-exports some of the most useful types for configuring and
-- interfacing with @oauthenticated@. More specific types,
-- constructors, and destructors are available in the specific type
-- modules below this in the hierarchy.
--

module Network.HTTP.Conduit.OAuth.Types (
  -- * Basic configuration types
  Request, ParameterMethod (..), SignatureMethod (..), Version (..),
  Callback (..), parseCallback,

  -- * Server Configuration
  Server (..), ThreeLeggedFlow (..),
  getResourceOwnerAuthorize, getTemporaryCredentialRequest, getTokenRequest, getCallback,
  parseThreeLeggedFlow,

  -- * Credentials
  Credentials, Token, Client, Temporary, Permanent,
  clientCredentials, temporaryCredentials, permanentCredentials, viewClientKey, viewTokenKey,

  -- * OAuth Parameterization
  Oa, freshOa, oa,
  ) where

import           Network.HTTP.Conduit.OAuth.Types.Basic
import           Network.HTTP.Conduit.OAuth.Types.Callback
import           Network.HTTP.Conduit.OAuth.Types.Credentials
import           Network.HTTP.Conduit.OAuth.Types.Params
import           Network.HTTP.Conduit.OAuth.Types.Server
