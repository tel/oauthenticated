{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}

-- |
-- Module      : Network.OAuth.Stateful
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.OAuth.Stateful
-- (
--   -- * An OAuth Monad Transformer
--   OAuthT, runOAuthT, runOAuthT',
-- 
--   -- * Standard operations
-- 
--   -- | These operations are similar to those exposed by
--   -- "Network.OAuth.Types.Params" or "Network.OAuth.Signing" but use the
--   -- OAuth monad state instead of needing manual threading.
--   oauth, sign, newParams,
-- 
--   -- * OAuth State
--   withGen, withManager
-- 
--   )
  where

import           Control.Applicative
import           Control.Monad.State
import           Crypto.Random
import           Network.HTTP.Client.Types       (Request)
import           Network.OAuth.MuLens
import qualified Network.OAuth.Signing           as S
import           Network.OAuth.Types.Credentials (Cred)
import           Network.OAuth.Types.Params      (Server (..))
import qualified Network.OAuth.Types.Params      as P
import           Pipes.Safe

import Network.HTTP.Client.Manager (Manager, ManagerSettings, closeManager,
                                    defaultManagerSettings, newManager)
-- | A simple monad suitable for basic OAuth requests.
newtype OAuthT ty m a =
  OAuthT { unOAuthT :: StateT (OAuthConfig ty) (SafeT m) a }
  deriving ( Functor, Applicative, Monad, MonadIO )

type instance Base (OAuthT ty m) = Base m

instance MonadTrans (OAuthT ty) where
    lift = OAuthT . lift . lift

runOAuthT :: (MonadIO m, MonadCatch m) => Cred ty -> Server -> OAuthT ty m a -> m a
runOAuthT = runOAuthT' defaultManagerSettings

runOAuthT' :: (MonadIO m, MonadCatch m) => ManagerSettings -> Cred ty -> Server -> OAuthT ty m a -> m a
runOAuthT' settings creds srv m = runSafeT $ do
  pool <- liftIO createEntropyPool
  bracket (liftIO $ newManager settings) (liftIO . closeManager) $ \man ->
    let conf = OAuthConfig man (cprgCreate pool) srv creds
    in  evalStateT (unOAuthT m) conf

-- | Generate default OAuth parameters and use them to sign a request. This
-- is the simplest OAuth method.
oauth :: MonadIO m => Request -> OAuthT ty m Request
oauth req = newParams >>= flip sign req

-- | 'OAuthT' retains a cryptographic random generator state.
withGen :: Monad m => (SystemRNG -> m (a, SystemRNG)) -> OAuthT ty m a
withGen = OAuthT . zoom crng . StateT . (lift .)

-- | 'OAuthT' retains a "Network.HTTP.Client" 'Manager'. The 'Manager' is
-- created at the beginning of an 'OAuthT' thread and destroyed at the end,
-- so it's efficient to pipeline many OAuth requests together.
withManager :: Monad m => (Manager -> m a) -> OAuthT ty m a
withManager f = OAuthT $ zoom manager (get >>= lift . lift . f)

-- | Create a fresh set of parameters.
newParams :: MonadIO m => OAuthT ty m (P.Oa ty)
newParams = do
  px <- withGen (liftIO . P.freshPin)
  c  <- OAuthT $ use credentials
  return P.Oa { P.credentials = c
              , P.workflow    = P.Standard
              , P.pin         = px
              }

-- | Sign a request using a set of parameters, 'P.Oa'.
sign :: Monad m => P.Oa ty -> Request -> OAuthT ty m Request
sign oax req = do
  s <- OAuthT $ use server
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
