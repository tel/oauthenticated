-- |
-- Module      : Network.OAuth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- OAuth tools for using @http-client@ for authenticated requests.
--
-- The functions here form the simplest basis for sending OAuthenticated
-- 'C.Request's. In order to generate credentials according to the OAuth
-- "three-legged workflow" use actions in the "Network.OAuth.ThreeLegged"
-- module.
--
module Network.OAuth (

  -- * Authenticating a request
  --
  -- | The 'oauthSimple' function can be used to sign a 'C.Request' as it
  -- stands. It should be performed just before the 'C.Request' is used as
  -- it uses the current timestamp and thus may only be valid for a limited
  -- amount of time.
  --
  -- 'oauthSimple' creates a /new/ random entropy pool every time it is
  -- called, thus it can be both slow and cryptographically dangerous to
  -- use it repeatedly as it can drain system entropy. Instead, the plain 'S.oauth'
  -- function should be used which allows for threading of the random
  -- source.
  --
  oauthSimple, S.oauth,

  -- * Lower-level and pure functionality
  --
  -- | When necessary to control or observe the signature more
  -- carefully, the lower level API can be used. This requires generating
  -- a fresh set of 'O.Oa' parameters from a relevant or deterministic
  -- 'O.OaPin' and then using 'S.sign' to sign the 'C.Request'.
  S.sign,
  
  -- ** Generating OAuth parameters
  O.emptyOa, O.freshOa, O.emptyPin, O.freshPin, 

  -- * OAuth Credentials
  O.Token (..), O.Cred, O.Client, O.Temporary, O.Permanent,

  -- ** Creating Credentials  
  O.clientCred, O.temporaryCred, O.permanentCred,
  O.fromUrlEncoded,

  -- * OAuth Configuration
  O.Server (..), O.defaultServer,
  O.ParameterMethod (..), O.SignatureMethod (..), O.Version (..),

  ) where

import qualified Crypto.Random                   as R
import qualified Network.HTTP.Client             as C
import qualified Network.OAuth.Signing           as S
import qualified Network.OAuth.Types.Credentials as O
import qualified Network.OAuth.Types.Params      as O

-- | Sign a request with a fresh set of parameters. Creates a fresh
-- 'R.ChaChaDRG' using new entropy for each signing and thus is potentially
-- /dangerous/ if used too frequently. In almost all cases, 'S.oauth'
-- should be used instead.
oauthSimple :: O.Cred ty -> O.Server -> C.Request -> IO C.Request
oauthSimple cr srv req = do
  entropy   <- R.drgNew
  (req', _) <- S.oauth cr srv req entropy
  return req'
