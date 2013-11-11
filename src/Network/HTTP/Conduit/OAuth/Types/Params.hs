{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE StandaloneDeriving #-}

-- |
-- Module      : Network.HTTP.Conduit.OAuth.Types.Params
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- /OAuth Parameters/
--
-- Broadly OAuth assumes there are two kinds of parameters: the
-- standard ones parsed either from a @www-form-urlencoded@-type body
-- or the querystring and the OAuth parameters themselves which may
-- eventually be encoded into the header, the body, or the querystring
-- (based on the value of 'ParameterMethod').
--
-- These are treated identically for signing purposes, but the OAuth
-- parameters can be thought of as being collected "above" the base
-- parameters and are linked to a particular OAuth request process.

module Network.HTTP.Conduit.OAuth.Types.Params (

  -- * OAuth Parameter Bundle
  Oa (..), oa, freshOa,

  -- ** Lensy access
  oaVersion, oaCredentials, oaToken, oaSignatureMethod, oaCallback,
  oaVerifier, oaTimestamp, oaNonce, oaSignature,

  -- ** Formatting
  oaDict, oaToHeader, oaToQuerystring, oaToEntityBody

  ) where

import           Control.Applicative
import           Control.Arrow
import           Control.Monad
import qualified Data.ByteString                              as S
import qualified Data.ByteString.Base16                       as S16
import qualified Data.ByteString.Char8                        as S8
import           Data.Maybe
import           Data.Monoid
import           Data.Time
import           Network.HTTP.Conduit.OAuth.Internal.ToHTTP
import           Network.HTTP.Conduit.OAuth.Types.Basic
import           Network.HTTP.Conduit.OAuth.Types.Callback
import           Network.HTTP.Conduit.OAuth.Types.Credentials
import           Network.HTTP.Conduit.OAuth.Types.Server
import           Network.HTTP.Conduit.OAuth.Util
import qualified Network.HTTP.Types                           as HTTP
import           System.Random

data Oa ty = Oa { _oaVersion         :: Version
                , _oaCredentials     :: Credentials ty
                , _oaToken           :: S.ByteString
                , _oaSignatureMethod :: SignatureMethod

                , _oaCallback        :: Maybe Callback
                  -- ^ only needed to get temporary creds
                , _oaVerifier        :: Maybe S.ByteString
                  -- ^ only used to get token creds

                , _oaTimestamp       :: UTCTime
                  -- ^ impurely generated per request
                , _oaNonce           :: S.ByteString
                  -- ^ impurely generated per request

                , _oaSignature       :: Maybe S.ByteString
                  -- ^ Generated in the final step
                }

oaVersion :: Functor f => (Version -> f Version) -> Oa ty -> f (Oa ty)
oaVersion inj oa =
  (\x -> oa { _oaVersion = x }) <$> inj (_oaVersion oa)

oaCredentials :: Functor f => (Credentials ty -> f (Credentials ty))
                 -> Oa ty -> f (Oa ty)
oaCredentials inj oa =
  (\x -> oa { _oaCredentials = x }) <$> inj (_oaCredentials oa)

oaToken :: Functor f => (S.ByteString -> f S.ByteString) -> Oa ty -> f (Oa ty)
oaToken inj oa =
  (\x -> oa { _oaToken = x }) <$> inj (_oaToken oa)

oaSignatureMethod :: Functor f => (SignatureMethod -> f SignatureMethod)
                     -> Oa ty -> f (Oa ty)
oaSignatureMethod inj oa =
  (\x -> oa { _oaSignatureMethod = x }) <$> inj (_oaSignatureMethod oa)

oaCallback :: Functor f => (Maybe Callback -> f (Maybe Callback))
              -> Oa ty -> f (Oa ty)
oaCallback inj oa =
  (\x -> oa { _oaCallback = x }) <$> inj (_oaCallback oa)

oaVerifier :: Functor f => (Maybe S.ByteString -> f (Maybe S.ByteString))
              -> Oa ty -> f (Oa ty)
oaVerifier inj oa =
  (\x -> oa { _oaVerifier = x }) <$> inj (_oaVerifier oa)

oaTimestamp :: Functor f => (UTCTime -> f UTCTime) -> Oa ty -> f (Oa ty)
oaTimestamp inj oa =
  (\x -> oa { _oaTimestamp = x }) <$> inj (_oaTimestamp oa)

oaNonce :: Functor f => (S.ByteString -> f S.ByteString)
           -> Oa ty -> f (Oa ty)
oaNonce inj oa =
  (\x -> oa { _oaNonce = x }) <$> inj (_oaNonce oa)

oaSignature :: Functor f => (Maybe S.ByteString -> f (Maybe S.ByteString))
               -> Oa ty -> f (Oa ty)
oaSignature inj oa =
  (\x -> oa { _oaSignature = x }) <$> inj (_oaSignature oa)

deriving instance Show (Oa Client)
deriving instance Show (Oa Temporary)
deriving instance Show (Oa Token)

-- | Creates a pure, unsigned 'Oa'. This does not include the
-- 'oaVerifier' so those must be added manually if used.
oa :: Credentials ty -> Server -> Maybe Callback -> UTCTime -> S.ByteString -> Oa ty
oa cred srv cb time nonce =
  Oa { _oaVersion         = view oauthVersion srv
     , _oaCredentials     = cred
     , _oaToken           = viewTokenKey cred
     , _oaSignatureMethod = view signatureMethod srv
     , _oaCallback        = cb
     , _oaVerifier        = Nothing
     , _oaTimestamp       = time
     , _oaNonce           = nonce
     , _oaSignature       = Nothing
     }

-- | Create a \"fresh\" 'Oa' for this exact moment---automatically
-- generates the 'oaNonce' and 'oaTimestamp' components.
freshOa :: Credentials ty -> Server -> Maybe Callback -> IO (Oa ty)
freshOa cred srv cb = oa cred srv cb
                      <$> getCurrentTime
                      <*> newNonce
  where newNonce = S16.encode . S.pack <$> replicateM 18 randomIO

oaDict :: Oa ty -> [(S.ByteString, S.ByteString)]
oaDict oax =
  catMaybes
  [ pair "oauth_version" . toHTTP           .$. view oaVersion oax
  , pair "oauth_consumer_key"               .$. view (oaCredentials . clientKey) oax
  , pair "oauth_signature_method" . toHTTP  .$. view oaSignatureMethod oax
  , pair "oauth_callback" . toHTTP          <$> view oaCallback oax
  , pair "oauth_verifier"                   <$> view oaVerifier oax
  , pair "oauth_token"                      .$. view (oaCredentials . to viewTokenKey) oax
  , pair "oauth_timestamp" . toHTTP         .$. view oaTimestamp oax
  , pair "oauth_nonce"                      .$. view oaNonce oax
  , pair "oauth_signature"                  <$> view oaSignature oax
  ]
  where
    -- <$> for when your parameter is pure
    infix 8 .$.
    f .$. a = f <$> pure a
    pair :: S.ByteString -> S.ByteString -> (S.ByteString, S.ByteString)
    pair = (,)

-- | Converts an 'Oa' to @Authorization:@ header format using an
-- optional @realm@ component.
oaToHeader :: Maybe S.ByteString -> Oa ty -> S.ByteString
oaToHeader mayRealm = finish . map param . oaDict
  where
    finish params = "OAuth " <> S8.intercalate ", " (addRealm mayRealm params)
    addRealm Nothing  params = params
    addRealm (Just r) params = param ("realm", r) : params
    param :: (S.ByteString, S.ByteString) -> S.ByteString
    param (p, v) = p <> "=\"" <> v <> "\""

-- | Converts an 'Oa' to query string format.
oaToQuerystring :: Oa ty -> HTTP.Query
oaToQuerystring = map (second Just) . oaDict

-- | Converts an 'Oa' to entity body format.
oaToEntityBody :: Oa ty -> [(S.ByteString, S.ByteString)]
oaToEntityBody = oaDict
