{-# LANGUAGE CPP                        #-}
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
module Network.OAuth.Simple (

  -- * A monad for authenticated requests
  --
  -- | "Network.OAuth.Simple" re-exports the "Network.OAuth" and
  -- "Network.Oauth.ThreeLegged" interfaces using the obvious 'StateT' and 'ReaderT'
  -- wrappers for tracking configuration, credentials, and random generator state.
  -- Managing 'C.Manager' state is out of scope for this module, but since 'OAuthT'
  -- is a monad transformer, it's easy enough to add another layer with the needed
  -- state.

  oauth, runOAuthSimple,

  -- ** More sophisticated interface
  runOAuth, runOAuthT, OAuthT (..), OAuth,

  -- * Configuration management
  upgradeCred, upgrade,

  -- * Configuration re-exports

  -- ** OAuth Credentials
  O.Token (..), O.Cred, O.Client, O.Temporary, O.Permanent,

  -- *** Creating Credentials
  O.clientCred, O.temporaryCred, O.permanentCred,
  O.fromUrlEncoded,

  -- ** OAuth Configuration
  O.Server (..), O.defaultServer,
  O.ParameterMethod (..), O.SignatureMethod (..), O.Version (..),

  -- ** Three-Legged Authorization

  -- *** Configuration types
  O.ThreeLegged (..), O.parseThreeLegged, O.Callback (..),
  O.Verifier,

  -- *** Actions
  requestTemporaryToken, buildAuthorizationUrl, requestPermanentToken,

  -- *** Example System
  requestTokenProtocol, TokenRequestFailure (..)

  ) where

#ifndef MIN_VERSION_base
#define MIN_VERSION_base(x,y,z) 1
#endif

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

import qualified Control.Monad.Catch             as E
import           Control.Monad.Reader
import           Control.Monad.Trans.Either
import qualified Crypto.Random                   as R
import qualified Data.ByteString.Lazy            as SL
import qualified Network.HTTP.Client             as C
import qualified Network.OAuth                   as O
import qualified Network.OAuth.ThreeLegged       as O
import qualified Network.OAuth.Types.Credentials as Cred
import           Network.URI                     (URI)

data OaConfig ty =
  OaConfig { cred        :: O.Cred ty
           , server      :: O.Server
           , threeLegged :: O.ThreeLegged
           }

-- | Perform authenticated requests using a shared 'C.Manager' and
-- a particular set of 'O.Cred's.
newtype OAuthT ty m a =
  OAuthT { unOAuthT :: ReaderT (OaConfig ty) m a }
  deriving ( Functor, Applicative, Monad
           , MonadReader (OaConfig ty)
           , E.MonadCatch
           , E.MonadThrow
           , MonadIO
           )
instance MonadTrans (OAuthT ty) where lift = OAuthT . lift

-- | 'OAuthT' wrapped over 'IO'.
type OAuth ty = OAuthT ty IO

-- | Run's an 'OAuthT' using a fresh 'R.EntropyPool'.
runOAuthT
  :: (MonadIO m) =>
     OAuthT ty m a -> O.Cred ty -> O.Server -> O.ThreeLegged ->
     m a
runOAuthT oat cr srv tl =
  runReaderT (unOAuthT oat) (OaConfig cr srv tl)

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

upgradeCred :: (Cred.ResourceToken ty', Monad m) => O.Token ty' -> OAuthT ty m (O.Cred ty')
upgradeCred tok = liftM (Cred.upgradeCred tok . cred) ask

-- | Given a 'Cred.ResourceToken' of some kind, run an inner 'OAuthT' session
-- with the same configuration but new credentials.
upgrade :: (Cred.ResourceToken ty', Monad m, MonadIO m, R.MonadRandom m) => O.Token ty' -> OAuthT ty' m a -> OAuthT ty m a
upgrade tok oat = do
  conf <- ask
  let conf' = conf { cred = Cred.upgradeCred tok (cred conf) }
  lift $ runReaderT (unOAuthT oat) conf'

liftBasic :: MonadIO m => (OaConfig ty -> IO a) -> OAuthT ty m a
liftBasic f = ask >>= liftIO . f

-- | Sign a request using fresh credentials.
oauth :: MonadIO m => C.Request -> OAuthT ty m C.Request
oauth req = liftBasic $ \conf -> O.oauth (cred conf) (server conf) req

-- Three-Legged Authorization
--------------------------------------------------------------------------------

requestTemporaryToken
  :: MonadIO m => C.Manager ->
     OAuthT O.Client m (C.Response (Either SL.ByteString (O.Token O.Temporary)))
requestTemporaryToken man =
  liftBasic $ \conf ->
    O.requestTemporaryToken (cred conf)
                            (server conf)
                            (threeLegged conf)
                            man

buildAuthorizationUrl :: Monad m => OAuthT O.Temporary m URI
buildAuthorizationUrl = do
  conf <- ask
  return $ O.buildAuthorizationUrl (cred conf) (threeLegged conf)

requestPermanentToken
  :: MonadIO m => C.Manager -> O.Verifier ->
     OAuthT O.Temporary m (C.Response (Either SL.ByteString (O.Token O.Permanent)))
requestPermanentToken man ver =
  liftBasic $ \conf ->
    O.requestPermanentToken (cred conf)
                            (server conf)
                            ver
                            (threeLegged conf)
                            man

data TokenRequestFailure =
    OnTemporaryRequest C.HttpException
  | BadTemporaryToken SL.ByteString
  | OnPermanentRequest C.HttpException
  | BadPermanentToken SL.ByteString
  deriving ( Show )

-- | Run a full Three-legged authorization protocol using the simple interface
-- of this module. This is similar to the 'O.requestTokenProtocol' in
-- "Network.OAuth.ThreeLegged", but offers better error handling due in part to
-- the easier management of configuration state.
requestTokenProtocol
  :: (Functor m, MonadIO m, R.MonadRandom m, E.MonadCatch m) =>
     C.Manager -> (URI -> m O.Verifier) ->
     OAuthT O.Client m (Either TokenRequestFailure (O.Cred O.Permanent))
requestTokenProtocol man getVerifier = runEitherT $ do
  -- Most of the code here is very simple, except that it does a LOT of
  -- exception lifting. Try to ignore the EitherT noise on the left side
  -- of each line.
  tempResp <- liftE OnTemporaryRequest $ E.try (requestTemporaryToken man)
  ttok     <- upE BadTemporaryToken $ C.responseBody tempResp
  upgradeE ttok $ do
    verifier <- lift $ buildAuthorizationUrl >>= lift . getVerifier
    permResp <- liftE OnPermanentRequest $ E.try (requestPermanentToken man verifier)
    ptok     <- upE BadPermanentToken $ C.responseBody permResp
    lift $ upgradeCred ptok
  where
    -- These functions explain most of the EitherT noise. They're largely
    -- useful for lifting default EitherT responses up into the error type
    -- we want.
    mapE     :: Functor m => (e -> f) -> EitherT e m b -> EitherT f m b
    mapE f = bimapEitherT f id
    liftE    :: Functor m => (e -> f) -> m (Either e b) -> EitherT f m b
    liftE f = mapE f . EitherT
    upE      :: (Monad m, Functor m) => (e -> f) -> Either e b -> EitherT f m b
    upE f = liftE f . return
    -- This is just 'upgrade' played out in the EitherT monad.
    upgradeE :: (Monad m, MonadIO m, R.MonadRandom m, Cred.ResourceToken ty') =>
                Cred.Token ty'
                -> EitherT e (OAuthT ty' m) a -> EitherT e (OAuthT ty m) a
    upgradeE tok = EitherT . upgrade tok . runEitherT
