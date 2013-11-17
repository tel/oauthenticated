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
import           Control.Monad.State
import           Crypto.Random
import           Network.HTTP.Client.Manager     (Manager)
import           Network.HTTP.Client.Types       (Request)
import           Network.OAuth.MuLens
import qualified Network.OAuth.Signing           as S
import           Network.OAuth.Types.Credentials (Cred, Permanent)
import           Network.OAuth.Types.Params      (Server (..))

-- | Very basic monad layer
type OAuthT ty m a = StateT (OAuthConfig ty) m a

-- | Sign a request.
oauth :: MonadIO m => Request -> OAuthT Permanent m Request
oauth req = do
  c <- use credentials
  s <- use server
  zoom crng $ StateT (liftIO . S.oauth c s req)

data OAuthConfig ty =
  OAuthConfig {-# UNPACK #-} !Manager
              {-# UNPACK #-} !SystemRNG
	      {-# UNPACK #-} !Server
	      {-# UNPACK #-} !(Cred ty)

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
