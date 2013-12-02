{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Network.OAuth.Simple
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Simplified Monadic interface for managing @http-client@ and
-- @oauthenticated@ state. Re-exposes all of the functionality from
-- "Network.OAuth" and "Network.OAuth.ThreeLegged".
--
module Network.OAuth.Simple where

import           Control.Applicative
import qualified Control.Monad.Catch       as E
import           Control.Monad.Reader
import           Control.Monad.State
import qualified Crypto.Random             as R
import qualified Network.HTTP.Client       as C
import qualified Network.OAuth             as O
import qualified Network.OAuth.ThreeLegged as O

data OaConfig ty =
  OaConfig { cred        :: O.Cred ty
           , manager     :: C.Manager
           , server      :: O.Server
           , threeLegged :: O.ThreeLegged
           }

-- | Perform authenticated requests using a shared 'C.Manager' and
-- a particular set of 'O.Cred's.
newtype OAuthT ty m a =
  OAuthT { unOAuthT :: ReaderT (OaConfig ty) (StateT R.SystemRNG m) a }
  deriving ( Functor, Applicative, Monad
           , MonadReader (OaConfig ty)
           , MonadState R.SystemRNG
           , E.MonadCatch
           , MonadIO
           )
instance MonadTrans (OAuthT ty) where lift = OAuthT . lift . lift

-- | 'OAuthT' wrapped over 'IO'.
type OAuth ty = OAuthT ty IO

-- | Run's an 'OAuthT' using a fresh 'C.Manager' and 'R.EntropyPool'. May
-- throw 'C.HttpException's.
runOAuthT'
  :: (MonadIO m, E.MonadCatch m) =>
     OAuthT ty m a -> O.Cred ty -> O.Server -> O.ThreeLegged -> 
     C.ManagerSettings ->
     m a
runOAuthT' oat cr srv tl mset = do
  entropy <- liftIO R.createEntropyPool
  E.bracket (liftIO $ C.newManager mset) (liftIO . C.closeManager) $ \man -> 
    evalStateT (runReaderT (unOAuthT oat) (OaConfig cr man srv tl)) (R.cprgCreate entropy)

-- | Run's an 'OAuthT' using a fresh 'C.Manager' generated using
-- 'C.defaultManagerSettings' and 'R  EntropyPool'. May throw 'C.HttpException's.
runOAuthT
  :: (MonadIO m, E.MonadCatch m) =>
     OAuthT ty m a -> O.Cred ty -> O.Server -> O.ThreeLegged -> 
     m a
runOAuthT oat cr srv tl = runOAuthT' oat cr srv tl C.defaultManagerSettings

runOAuth :: OAuth ty a -> O.Cred ty -> O.Server -> O.ThreeLegged -> IO a
runOAuth = runOAuthT

-- | The simplest way to execute a set of authenticated requests. Produces
-- invalid 'ThreeLegged' requests---use 'runOAuth' to provide 'O.Server' and
-- 'O.ThreeLegged' configuration information.
runOAuthSimple :: OAuth ty a -> O.Cred ty -> IO a
runOAuthSimple oat cr = runOAuth oat cr O.defaultServer tl where
  Just tl = O.parseThreeLegged "http://example.com" 
                               "http://example.com" 
                               "http://example.com" 
                               O.OutOfBand
