-- |
-- Module      : Network.OAuth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.OAuth where

import           Control.Applicative
import           Control.Monad.State
import           Crypto.Random
import           Network.HTTP.Client.Manager     (Manager)
import           Network.HTTP.Client.Types       (Request)
import           Network.OAuth.MuLens
import           Network.OAuth.Signing           (sign)
import           Network.OAuth.Types.Credentials (Client, Cred, Permanent,
                                                  Temporary, Token, key, secret)
import           Network.OAuth.Types.Params      (ParameterMethod (..),
                                                  Server (..),
                                                  SignatureMethod (..),
                                                  Workflow (..))
import qualified Network.OAuth.Types.Params      as P
import Network.OAuth.Stateful


-- | Very basic monad layer
type OAuthT ty m a = StateT (OAuthConfig ty) m a

-- | Sign a request.
oauth :: MonadIO m => Request -> OAuthT Permanent m Request
oauth req = do
  c <- use credentials
  s <- use server
  zoom crng $ StateT (liftIO . oauth' c s req)

-- | Sign a request.
oauth' :: CPRG gen => Cred Permanent -> Server -> Request -> gen -> IO (Request, gen)
oauth' creds sv req gen = do
  (pinx, gen') <- P.freshPin gen
  let oax = P.Oa { P.credentials = creds, P.workflow = Standard, P.pin = pinx }
  return $ (sign oax sv req, gen')
