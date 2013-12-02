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
  runOAuth, runOAuthT,

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
  requestTokenProtocol

  ) where

import           Control.Applicative
import qualified Control.Monad.Catch             as E
import           Control.Monad.Reader
import           Control.Monad.State
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

-- | Run's an 'OAuthT' using a fresh 'R.EntropyPool'.
runOAuthT
  :: (MonadIO m) =>
     OAuthT ty m a -> O.Cred ty -> O.Server -> O.ThreeLegged ->
     m a
runOAuthT oat cr srv tl = do
  entropy <- liftIO R.createEntropyPool
  evalStateT (runReaderT (unOAuthT oat) (OaConfig cr srv tl)) (R.cprgCreate entropy)

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
upgrade :: (Cred.ResourceToken ty', Monad m) => O.Token ty' -> OAuthT ty' m a -> OAuthT ty m a
upgrade tok oat = do
  gen  <- state R.cprgFork
  conf <- ask
  let conf' = conf { cred = Cred.upgradeCred tok (cred conf) }
  lift $ evalStateT (runReaderT (unOAuthT oat) conf') gen

liftBasic :: MonadIO m => (R.SystemRNG -> OaConfig ty -> IO (a, R.SystemRNG)) -> OAuthT ty m a
liftBasic f = do
  gen  <- get
  conf <- ask
  (a, gen') <- liftIO (f gen conf)
  put gen'
  return a

-- | Sign a request using fresh credentials.
oauth :: MonadIO m => C.Request -> OAuthT ty m C.Request
oauth req = liftBasic $ \gen conf -> O.oauth (cred conf) (server conf) req gen

-- Three-Legged Authorization
--------------------------------------------------------------------------------

requestTemporaryToken
  :: MonadIO m => C.Manager ->
     OAuthT O.Client m (C.Response (Either SL.ByteString (O.Token O.Temporary)))
requestTemporaryToken man =
  liftBasic $ \gen conf ->
    O.requestTemporaryToken (cred conf)
                            (server conf)
                            (threeLegged conf)
                            man
                            gen

buildAuthorizationUrl :: Monad m => OAuthT O.Temporary m URI
buildAuthorizationUrl = do
  conf <- ask
  return $ O.buildAuthorizationUrl (cred conf) (threeLegged conf)

requestPermanentToken
  :: MonadIO m => C.Manager -> O.Verifier ->
     OAuthT O.Temporary m (C.Response (Either SL.ByteString (O.Token O.Permanent)))
requestPermanentToken man ver =
  liftBasic $ \gen conf ->
    O.requestPermanentToken (cred conf)
                            (server conf)
                            ver
                            (threeLegged conf)
                            man
                            gen

data TokenRequestFailure =
    HttpExceptionOnTemporaryRequest C.HttpException
  | BadTemporaryToken SL.ByteString
  | HttpExceptionOnPermanentRequest C.HttpException
  | BadPermanentToken SL.ByteString
  deriving ( Show )

mapE :: Functor m => (e -> f) -> EitherT e m a -> EitherT f m a
mapE f = bimapEitherT f id

-- | Run a full Three-legged authorization protocol using the simple interface
-- of this module. This is similar to the 'O.requestTokenProtocol' in
-- "Network.OAuth.ThreeLegged", but offers better error handling due in part to
-- the easier management of configuration state.
requestTokenProtocol
  :: (Functor m, MonadIO m, E.MonadCatch m) =>
     C.Manager -> (URI -> m O.Verifier) ->
     OAuthT O.Client m (Either TokenRequestFailure (O.Cred O.Permanent))
requestTokenProtocol man getVerifier = runEitherT $ do
  tempResp <- 
    mapE HttpExceptionOnTemporaryRequest 
    $ EitherT $ E.try (requestTemporaryToken man)
  case C.responseBody tempResp of
    Left lbs -> left $ BadTemporaryToken lbs
    Right ttok -> EitherT $ upgrade ttok $ runEitherT $ do
      authUrl  <- lift buildAuthorizationUrl
      verifier <- lift $ lift $ getVerifier authUrl
      permResp <-
        mapE HttpExceptionOnPermanentRequest 
        $ EitherT $ E.try (requestPermanentToken man verifier)
      case C.responseBody permResp of
        Left lbs  -> left $ BadPermanentToken lbs
        Right ptok -> lift (upgradeCred ptok)
