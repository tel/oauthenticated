-- |
-- Module      : Network.OAuth.Stateful
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.OAuth.Stateful where

import           Control.Applicative
import qualified Control.Exception               as E
import           Control.Monad.State
import           Crypto.Random
import           Network.HTTP.Client.Manager     (Manager, ManagerSettings)
import           Network.HTTP.Client.Manager     (closeManager, newManager)
import           Network.HTTP.Client.Types       (Request)
import           Network.OAuth.MuLens
import qualified Network.OAuth.Signing           as S
import           Network.OAuth.Types.Credentials (Cred)
import           Network.OAuth.Types.Params      (Server (..))
import qualified Network.OAuth.Types.Params      as P

-- | Very basic monad layer
type OAuthT ty m a = StateT (OAuthConfig ty) m a

-- | Build a new 'Manager' and 'CPRG' to run an isolated set of 'OAuth'
-- requests.
runOAuth :: ManagerSettings -> Server -> Cred ty -> OAuthT ty IO a -> IO a
runOAuth settings svr c mon = do
  fst <$> E.bracket (newManager settings) closeManager (\man -> runOAuthT' svr c man mon)

-- | Run an 'OAuthT' monad while continuing to thread the 'Manager'. This can
-- be more efficient if 'OAuth' requests are only a fraction of the total
-- request volume.
runOAuthT' :: MonadIO m => Server -> Cred ty -> Manager -> OAuthT ty m a -> m (a, OAuthConfig ty)
runOAuthT' srv c m mon = runStateT mon =<< conf where
  conf = do
    pool <- liftIO createEntropyPool
    return $ OAuthConfig m (cprgCreate pool) srv c

-- | Generate default OAuth parameters and use them to sign a request.
oauth :: MonadIO m => Request -> OAuthT ty m Request
oauth req = do
  oax <- newParams
  sign oax req

withGen :: MonadIO m => (SystemRNG -> m (a, SystemRNG)) -> OAuthT ty m a
withGen m = zoom crng $ StateT m

newParams :: MonadIO m => OAuthT ty m (P.Oa ty)
newParams = do
  px <- withGen (liftIO . P.freshPin)
  c <- use credentials
  return P.Oa { P.credentials = c
              , P.workflow    = P.Standard
              , P.pin         = px
              }

-- | Sign a request.
sign :: Monad m => P.Oa ty -> Request -> OAuthT ty m Request
sign oax req = do
  s <- use server
  return (S.sign oax s req)

data OAuthConfig ty =
  OAuthConfig {-# UNPACK #-} !Manager
              {-# UNPACK #-} !SystemRNG
	      {-# UNPACK #-} !Server
	      !(Cred ty)

manager :: Lens (OAuthConfig ty) (OAuthConfig ty) Manager Manager
manager inj (OAuthConfig m rng sv c) = (\m' -> OAuthConfig m' rng sv c) <$> inj m
{-# INLINE manager #-}

crng :: Lens (OAuthConfig ty) (OAuthConfig ty) SystemRNG SystemRNG
crng inj (OAuthConfig m rng sv c) = (\rng' -> OAuthConfig m rng' sv c) <$> inj rng
{-# INLINE crng #-}

server :: Lens (OAuthConfig ty) (OAuthConfig ty) Server Server
server inj (OAuthConfig m rng sv c) = (\sv' -> OAuthConfig m rng sv' c) <$> inj sv
{-# INLINE server #-}

credentials :: Lens (OAuthConfig ty) (OAuthConfig ty') (Cred ty) (Cred ty')
credentials inj (OAuthConfig m rng sv c) = OAuthConfig m rng sv <$> inj c
{-# INLINE credentials #-}
