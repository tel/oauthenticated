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
  ThreeLegged (..), parseThreeLegged, Callback (..),

  -- * Actions
  requestTemporaryToken, buildAuthorizationUrl, requestPermanentToken,

  -- ** Raw forms
  requestTemporaryTokenRaw, requestPermanentTokenRaw,

  -- * Example system
  requestTokenProtocol
  ) where

import           Control.Applicative
import           Control.Monad.Trans
import           Control.Monad.Trans.Maybe
import qualified Data.ByteString.Lazy            as SL
import qualified Data.ByteString                 as S
import           Data.Data
import           Network.HTTP.Client             (httpLbs)
import           Network.HTTP.Client.Request     (getUri,parseUrl)
import           Network.HTTP.Client.Types       (Request (..), Response (..), HttpException)
import           Network.HTTP.Types              (renderQuery)
import           Network.OAuth
import           Network.OAuth.MuLens
import           Network.OAuth.Stateful
import           Network.OAuth.Types.Credentials
import           Network.OAuth.Types.Params
import           Network.URI

-- | Data parameterizing the \"Three-legged OAuth\" redirection-based
-- authorization protocol. These parameters cover the protocol as described
-- in the community editions /OAuth Core 1.0/ and /OAuth Core 1.0a/ as well
-- as RFC 5849.
data ThreeLegged =
  ThreeLegged { temporaryTokenRequest :: Request
              -- ^ Base 'Request' for the \"endpoint used by the client to
              -- obtain a set of 'Temporary' 'Cred'entials\" in the form of
              -- a 'Temporary' 'Token'. This request is automatically
              -- instantiated and performed during the first leg of the
              -- 'ThreeLegged' authorization protocol.
              , resourceOwnerAuthorization :: Request
              -- ^ Base 'Request' for the \"endpoint to which the resource
              -- owner is redirected to grant authorization\". This request
              -- must be performed by the user granting token authorization
              -- to the client. Transmitting the parameters of this request
              -- to the user is out of scope of @oauthenticated@, but
              -- functions are provided to make it easier.
              , permanentTokenRequest      :: Request
              -- ^ Base 'Request' for the \"endpoint used by the client to
              -- request a set of token credentials using the set of
              -- 'Temporary' 'Cred'entials\". This request is also
              -- instantiated and performed by @oauthenticated@ in order to
              -- produce a 'Permanent' 'Token'.
              , callback                   :: Callback
              -- ^ The 'Callback' parameter configures how the user is
              -- intended to communicate the 'Verifier' back to the client.
              }
    deriving ( Show, Typeable )

-- | Convenience method for creating a 'ThreeLegged' configuration from
-- a trio of URLs and a 'Callback'.
parseThreeLegged :: String -> String -> String -> Callback -> Either HttpException ThreeLegged
parseThreeLegged a b c d = ThreeLegged <$> parseUrl a <*> parseUrl b <*> parseUrl c <*> pure d

-- | Request a 'Temporary' 'Token' based on the parameters of
-- a 'ThreeLegged' protocol. This returns the raw response which should be
-- encoded as @www-form-urlencoded@.
requestTemporaryTokenRaw :: MonadIO m => ThreeLegged -> OAuthT Client m SL.ByteString
requestTemporaryTokenRaw (ThreeLegged {..}) = do
  oax  <- newParams
  req  <- sign (oax { workflow = TemporaryTokenRequest callback }) temporaryTokenRequest
  resp <- withManager (liftIO . httpLbs req)
  return $ responseBody resp

-- | Returns 'Nothing' if the response could not be decoded as a 'Token'.
-- Importantly, in RFC 5849 compliant modes this requires that the token
-- response includes @callback_confirmed=true@. See also
-- 'requestTemporaryTokenRaw'.
requestTemporaryToken :: MonadIO m => ThreeLegged -> OAuthT Client m (Maybe (Token Temporary))
requestTemporaryToken tl = do
  raw <- requestTemporaryTokenRaw tl
  s   <- getServer
  let mayToken = fromUrlEncoded $ SL.toStrict raw
  return $ do
    (confirmed, tok) <- mayToken
    case oAuthVersion s of
      OAuthCommunity1 -> return tok
      _               -> if confirmed then return tok else fail "Must be confirmed"

-- | Produce a 'URI' which the user should be directed to in order to
-- authorize a set of 'Temporary' 'Cred's.
buildAuthorizationUrl :: Monad m => ThreeLegged -> OAuthT Temporary m URI
buildAuthorizationUrl (ThreeLegged {..}) = do
  c <- getCredentials
  return $ getUri $ resourceOwnerAuthorization {
    queryString = renderQuery True [ ("oauth_token", Just (c ^. resourceToken . key)) ]
  }

-- | Request a 'Permanent 'Token' based on the parameters of
-- a 'ThreeLegged' protocol. This returns the raw response which should be
-- encoded as @www-form-urlencoded@.
requestPermanentTokenRaw :: MonadIO m => ThreeLegged -> Verifier -> OAuthT Temporary m SL.ByteString
requestPermanentTokenRaw (ThreeLegged {..}) verifier = do
  oax  <- newParams
  req  <- sign (oax { workflow = PermanentTokenRequest verifier }) permanentTokenRequest
  resp <- withManager (liftIO . httpLbs req)
  return $ responseBody resp

-- | Returns 'Nothing' if the response could not be decoded as a 'Token'.
-- See also 'requestPermanentTokenRaw'.
requestPermanentToken :: MonadIO m => ThreeLegged -> Verifier -> OAuthT Temporary m (Maybe (Token Permanent))
requestPermanentToken tl verifier = do
  raw <- requestPermanentTokenRaw tl verifier
  return $ fmap snd $ fromUrlEncoded $ SL.toStrict raw

-- | Performs an interactive token request over stdin assuming that the
-- verifier code is acquired out-of-band.
requestTokenProtocol :: MonadIO m => ThreeLegged -> OAuthT Client m (Maybe (Token Permanent))
requestTokenProtocol threeLegged = runMaybeT $ do
  cCred <- lift getCredentials
  tok <- MaybeT (requestTemporaryToken threeLegged)
  MaybeT $ withCred (temporaryCred tok cCred) $ do
    url <- buildAuthorizationUrl threeLegged
    code <- liftIO $ do 
      putStr "Please direct the user to the following address\n\n"
      putStr "    " >> print url >> putStr "\n\n"
      putStrLn "... then enter the verification code below (no spaces)\n"
      S.getLine
    requestPermanentToken threeLegged code
