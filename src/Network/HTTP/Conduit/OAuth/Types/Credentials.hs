{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE StandaloneDeriving    #-}

-- |
-- Module      : Network.HTTP.Conduit.OAuth.Types.Credentials
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.HTTP.Conduit.OAuth.Types.Credentials (

  -- * Types of Credentials
  Credentials (..), Token (..), Client, Temporary, Permanent,

  -- * Component Access
  clientKey, clientSecret,

  -- 'Temporary' and 'Token' credentials specialize 'Client'
  -- credentials and thus instantiate the 'HasToken' class.
  HasToken (..),

  -- ** Basic
  viewClientKey, viewClientSecret, viewTokenKey, viewTokenSecret,
  viewTokenKey', viewTokenSecret',

  -- * Building and upgrading credentials
  clientCredentials, temporaryCredentials, permanentCredentials,

  -- * Signing
  signingKey

  ) where

import           Control.Applicative
import qualified Data.ByteString                 as S
import           Data.Monoid
import           Network.HTTP.Conduit.OAuth.Util
import qualified Network.HTTP.Types              as HTTP

-- Credentials
--------------------------------------------------------------------------------

-- Several types index the kinds of 'Credentials' we might have.

-- | 'Client' 'Credentials' reflect only the client's identity. They
-- are core credentials in that the other two augment 'Client'
-- 'Credentials' with further token information.
data Client

-- | 'Temporary' 'Credentials' are 'Client' 'Credentials' augmented
-- with a temporary token good only for requesting a single user to
-- authorize a single client a single time.
data Temporary

-- | 'Permanent' 'Credentials' are credentials which provide a client
-- access to a user's protected resource *semi-permanently*.
data Permanent

-- | A 'Token' is the very component which elevates 'Client'
-- 'Credentials' to 'Temporary' or 'Permanent' 'Credentials'.
data Token ty =
  Token { tokKey    :: S.ByteString
        , tokSecret :: S.ByteString
        } deriving ( Show, Eq, Ord )

-- | Credentials are created at various points during the OAuth
-- handshakes. Each time they are a pair of a key and a secret, the
-- first of which being public the second private.
data Credentials ty where
  ClientCredentials :: S.ByteString -> S.ByteString -> Credentials Client
  TemporaryCredentials :: Credentials Client -> Token Temporary -> Credentials Temporary
  PermanentCredentials :: Credentials Client -> Token Permanent -> Credentials Permanent

deriving instance Eq (Credentials ty)
deriving instance Show (Credentials ty)


clientKey :: Functor f => (S.ByteString -> f S.ByteString)
          -> Credentials ty -> f (Credentials ty)
clientKey inj (ClientCredentials k s) = (`ClientCredentials` s) <$> inj k
clientKey inj (TemporaryCredentials (ClientCredentials k s) tok) =
  (\k' -> TemporaryCredentials (ClientCredentials k' s) tok) <$> inj k
clientKey inj (PermanentCredentials (ClientCredentials k s) tok) =
  (\k' -> PermanentCredentials (ClientCredentials k' s) tok) <$> inj k
{-# INLINE clientKey #-}

clientSecret :: Functor f => (S.ByteString -> f S.ByteString)
          -> Credentials ty -> f (Credentials ty)
clientSecret inj (ClientCredentials k s) = ClientCredentials k <$> inj s
clientSecret inj (TemporaryCredentials (ClientCredentials k s) tok) =
  (\s' -> TemporaryCredentials (ClientCredentials k s') tok) <$> inj s
clientSecret inj (PermanentCredentials (ClientCredentials k s) tok) =
  (\s' -> PermanentCredentials (ClientCredentials k s') tok) <$> inj s
{-# INLINE clientSecret #-}

-- | 'Credentials' with tokens are 'Temporary' or 'Permanent'
-- 'Credentials'. 'Client' 'Credentials' always have empty tokens, so
-- we can't access that part with a lens.
class HasToken ty c where
  token
    :: Functor f => (Token ty -> f (Token ty))
       -> c ty -> f (c ty)
  tokenKey
    :: Functor f => (S.ByteString -> f S.ByteString)
       -> c ty -> f (c ty)
  tokenSecret
    :: Functor f => (S.ByteString -> f S.ByteString)
       -> c ty -> f (c ty)

instance HasToken Temporary Token where
  token = id
  {-# INLINE token #-}
  tokenKey inj (Token k s) = (`Token` s) <$> inj k
  {-# INLINE tokenKey #-}
  tokenSecret inj (Token k s) = Token k <$> inj s
  {-# INLINE tokenSecret #-}

instance HasToken Permanent Token where
  token = id
  {-# INLINE token #-}
  tokenKey inj (Token k s) = (`Token` s) <$> inj k
  {-# INLINE tokenKey #-}
  tokenSecret inj (Token k s) = Token k <$> inj s
  {-# INLINE tokenSecret #-}

instance HasToken Temporary Credentials where
  token inj (TemporaryCredentials cred tok) =
    TemporaryCredentials cred <$> inj tok
  tokenKey = token . tokenKey
  {-# INLINE tokenKey #-}
  tokenSecret = token . tokenSecret
  {-# INLINE tokenSecret #-}

instance HasToken Permanent Credentials where
  token inj (PermanentCredentials cred tok) =
    PermanentCredentials cred <$> inj tok
  tokenKey = token . tokenKey
  {-# INLINE tokenKey #-}
  tokenSecret = token . tokenSecret
  {-# INLINE tokenSecret #-}

viewClientKey :: Credentials ty -> S.ByteString
viewClientKey = view clientKey
{-# INLINE viewClientKey #-}

viewClientSecret :: Credentials ty -> S.ByteString
viewClientSecret = view clientSecret
{-# INLINE viewClientSecret #-}

viewTokenKey :: HasToken ty t => t ty -> S.ByteString
viewTokenKey = view tokenKey
{-# INLINE viewTokenKey #-}

-- | 'viewTokenKey' with defaults for 'Credentials' not instantiating
-- 'HasToken'.
viewTokenKey' :: Credentials ty -> S.ByteString
viewTokenKey' ClientCredentials{} = S.empty
viewTokenKey' creds@TemporaryCredentials{} = view tokenKey creds
viewTokenKey' creds@PermanentCredentials{} = view tokenKey creds
{-# INLINE viewTokenKey' #-}

viewTokenSecret :: HasToken ty t => t ty -> S.ByteString
viewTokenSecret = view tokenSecret
{-# INLINE viewTokenSecret #-}

-- | 'viewTokenSecret' with defaults for 'Credentials' not
-- instantiating 'HasToken'.
viewTokenSecret' :: Credentials ty -> S.ByteString
viewTokenSecret' ClientCredentials{}    = S.empty
viewTokenSecret' creds@TemporaryCredentials{} = view tokenSecret creds
viewTokenSecret' creds@PermanentCredentials{} = view tokenSecret creds
{-# INLINE viewTokenSecret' #-}

-- | Creates a signing key based on the kind of credentials currently
-- possessed. This function automatically handles imputing blank token
-- components for 'Client' 'Credentials'.
signingKey :: Credentials ty -> S.ByteString
signingKey creds =
  HTTP.urlEncode True (view clientSecret creds)
  <> "&" <>
  HTTP.urlEncode True (viewTokenSecret' creds)

-- | Build basic 'Client' 'Credentials' from client token and client
-- token secret componenets.
clientCredentials :: (S.ByteString, S.ByteString) -> Credentials Client
clientCredentials = uncurry ClientCredentials

-- | Upgrade 'Client' 'Credentials' to 'Temporary' 'Credential's by
-- adding in the temporary token and temporary token secret
-- componenets.
temporaryCredentials :: Token Temporary -> Credentials Client -> Credentials Temporary
temporaryCredentials = flip TemporaryCredentials
{-# INLINE temporaryCredentials #-}

-- | Upgrade any set of 'Credentials' to 'Token' 'Credentials' by
-- adding in the token and token secret componenets.
permanentCredentials :: Token Permanent -> Credentials ty -> Credentials Permanent
permanentCredentials tok cred@ClientCredentials{}    = PermanentCredentials cred tok
permanentCredentials tok (TemporaryCredentials cc _) = PermanentCredentials cc tok
permanentCredentials tok (PermanentCredentials cc _) = PermanentCredentials cc tok
{-# INLINE permanentCredentials #-}
