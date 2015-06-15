{-# LANGUAGE CPP                #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}

-- |
-- Module      : Network.OAuth.ThreeLegged
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- The \"Three-legged OAuth\" protocol implementing RFC 5849's
-- /Redirection-Based Authorization/.

module Network.OAuth.ThreeLegged (
  -- * Configuration types
  ThreeLegged (..), parseThreeLegged, P.Callback (..),

  P.Verifier,

  -- * Actions
  requestTemporaryToken, buildAuthorizationUrl, requestPermanentToken,

  -- ** Raw forms
  requestTemporaryTokenRaw, requestPermanentTokenRaw,

  -- * Example system
  requestTokenProtocol, requestTokenProtocol'
  ) where

#ifndef MIN_VERSION_base
#define MIN_VERSION_base(x,y,z) 1
#endif

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

import           Control.Exception               as E
import           Control.Monad.IO.Class          (MonadIO, liftIO)
import qualified Crypto.Random                   as R
import qualified Data.ByteString.Lazy            as SL
import           Data.Data
import qualified Network.HTTP.Client             as C
import           Network.HTTP.Types              (renderQuery)
import qualified Network.OAuth                   as O
import           Network.OAuth.MuLens
import qualified Network.OAuth.Types.Credentials as Cred
import qualified Network.OAuth.Types.Params      as P
import           Network.URI

-- | Data parameterizing the \"Three-legged OAuth\" redirection-based
-- authorization protocol. These parameters cover the protocol as described
-- in the community editions /OAuth Core 1.0/ and /OAuth Core 1.0a/ as well
-- as RFC 5849.
data ThreeLegged =
  ThreeLegged { temporaryTokenRequest      :: C.Request
              -- ^ Base 'Request' for the \"endpoint used by the client to
              -- obtain a set of 'Temporary' 'Cred'entials\" in the form of
              -- a 'Temporary' 'Token'. This request is automatically
              -- instantiated and performed during the first leg of the
              -- 'ThreeLegged' authorization protocol.
              , resourceOwnerAuthorization :: C.Request
              -- ^ Base 'Request' for the \"endpoint to which the resource
              -- owner is redirected to grant authorization\". This request
              -- must be performed by the user granting token authorization
              -- to the client. Transmitting the parameters of this request
              -- to the user is out of scope of @oauthenticated@, but
              -- functions are provided to make it easier.
              , permanentTokenRequest      :: C.Request
              -- ^ Base 'Request' for the \"endpoint used by the client to
              -- request a set of token credentials using the set of
              -- 'Temporary' 'Cred'entials\". This request is also
              -- instantiated and performed by @oauthenticated@ in order to
              -- produce a 'Permanent' 'Token'.
              , callback                   :: P.Callback
              -- ^ The 'Callback' parameter configures how the user is
              -- intended to communicate the 'Verifier' back to the client.
              }
    deriving ( Show, Typeable )

-- | Convenience method for creating a 'ThreeLegged' configuration from
-- a trio of URLs and a 'Callback'. Returns 'Nothing' if one of the
-- callback URLs could not be parsed correctly.
parseThreeLegged :: String -> String -> String -> P.Callback -> Maybe ThreeLegged
parseThreeLegged a b c d =
  ThreeLegged <$> C.parseUrl a
              <*> C.parseUrl b
              <*> C.parseUrl c
              <*> pure d

-- | Request a 'Temporary' 'Token' based on the parameters of
-- a 'ThreeLegged' protocol. This returns the raw response which should be
-- encoded as @www-form-urlencoded@.
--
-- Throws 'C.HttpException's.
requestTemporaryTokenRaw
  :: (MonadIO io, R.MonadRandom io)
  => O.Cred O.Client -> O.Server -> ThreeLegged -> C.Manager
  -> io (C.Response SL.ByteString)
requestTemporaryTokenRaw cr srv (ThreeLegged {..}) man = do
  oax <- O.freshOa cr
  let req = O.sign (oax { P.workflow = P.TemporaryTokenRequest callback }) srv temporaryTokenRequest
  liftIO $ C.httpLbs req man

-- | Returns the raw result if the 'C.Response' could not be parsed as
-- a valid 'O.Token'.  Importantly, in RFC 5849 compliant modes this
-- requires that the token response includes @callback_confirmed=true@. See
-- also 'requestTemporaryTokenRaw'.
--
-- Throws 'C.HttpException's.
requestTemporaryToken
  :: (MonadIO io, R.MonadRandom io)
  => O.Cred O.Client -> O.Server -> ThreeLegged -> C.Manager
  -> io (C.Response (Either SL.ByteString (O.Token O.Temporary)))
requestTemporaryToken cr srv tl man = do
  raw <- requestTemporaryTokenRaw cr srv tl man
  return (tryParseToken <$> raw)
  where
    tryParseToken lbs = case maybeParseToken lbs of
      Nothing  -> Left lbs
      Just tok -> Right tok
    maybeParseToken lbs =
      do (confirmed, tok) <- O.fromUrlEncoded $ SL.toStrict lbs
         case P.oAuthVersion srv of
           O.OAuthCommunity1 -> return tok
           _                 -> if confirmed then return tok else fail "Must be confirmed"

-- | Produce a 'URI' which the user should be directed to in order to
-- authorize a set of 'Temporary' 'Cred's.
buildAuthorizationUrl :: O.Cred O.Temporary -> ThreeLegged -> URI
buildAuthorizationUrl cr (ThreeLegged {..}) =
  C.getUri $ resourceOwnerAuthorization {
    C.queryString = renderQuery True [ ("oauth_token", Just (cr ^. Cred.resourceToken . Cred.key)) ]
  }

-- | Request a 'Permanent 'Token' based on the parameters of
-- a 'ThreeLegged' protocol. This returns the raw response which should be
-- encoded as @www-form-urlencoded@.
--
-- Throws 'C.HttpException's.
requestPermanentTokenRaw
  :: (MonadIO io, R.MonadRandom io)
  => O.Cred O.Temporary -> O.Server -> P.Verifier -> ThreeLegged -> C.Manager
  -> io (C.Response SL.ByteString)
requestPermanentTokenRaw cr srv verifier (ThreeLegged {..}) man = do
  oax <- O.freshOa cr
  let req = O.sign (oax { P.workflow = P.PermanentTokenRequest verifier }) srv permanentTokenRequest
  liftIO $ C.httpLbs req man

-- | Returns 'Nothing' if the response could not be decoded as a 'Token'.
-- See also 'requestPermanentTokenRaw'.
--
-- Throws 'C.HttpException's.
requestPermanentToken
  :: (MonadIO io, R.MonadRandom io)
  => O.Cred O.Temporary -> O.Server -> P.Verifier -> ThreeLegged -> C.Manager
  -> io (C.Response (Either SL.ByteString (O.Token O.Permanent)))
requestPermanentToken cr srv verifier tl man = do
  raw <- requestPermanentTokenRaw cr srv verifier tl man
  return (tryParseToken <$> raw)
  where
    tryParseToken lbs = case maybeParseToken lbs of
      Nothing  -> Left lbs
      Just tok -> Right tok
    maybeParseToken = fmap snd . O.fromUrlEncoded . SL.toStrict

-- | Like 'requestTokenProtocol' but allows for specification of the
-- 'C.ManagerSettings'.
requestTokenProtocol'
  :: C.ManagerSettings -> O.Cred O.Client -> O.Server -> ThreeLegged
     -> (URI -> IO P.Verifier)
     -> IO (Maybe (O.Cred O.Permanent))
requestTokenProtocol' mset cr srv tl getVerifier =
  E.bracket (C.newManager mset) C.closeManager $ \man -> do
    respTempToken <- requestTemporaryToken cr srv tl man
    case C.responseBody respTempToken of
      Left _ -> return Nothing
      Right tok -> do
        let tempCr = O.temporaryCred tok cr
        verifier <- getVerifier $ buildAuthorizationUrl tempCr tl
        respPermToken <- requestPermanentToken tempCr srv verifier tl man
        case C.responseBody respPermToken of
          Left _ -> return Nothing
          Right tok' -> return (Just $ O.permanentCred tok' cr)

-- | Performs an interactive token request provided credentials,
-- configuration, and a way to convert a user authorization 'URI' into
-- a 'P.Verifier' out of band. Does not use any kind of TLS protection---it
-- will throw a 'C.TlsNotSupported' exception if TLS is required.
--
-- Throws 'C.HttpException's.
requestTokenProtocol
  :: O.Cred O.Client -> O.Server -> ThreeLegged
     -> (URI -> IO P.Verifier)
     -> IO (Maybe (O.Cred O.Permanent))
requestTokenProtocol = requestTokenProtocol' C.defaultManagerSettings


  -- cCred <- lift getCredentials
  -- tok <- MaybeT (requestTemporaryToken threeLegged)
  -- MaybeT $ withCred (temporaryCred tok cCred) $ do
  --   url <- buildAuthorizationUrl threeLegged
  --   code <- liftIO $ do
  --     putStr "Please direct the user to the following address\n\n"
  --     putStr "    " >> print url >> putStr "\n\n"
  --     putStrLn "... then enter the verification code below (no spaces)\n"
  --     S.getLine
  --   requestPermanentToken threeLegged code
