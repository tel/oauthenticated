{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs             #-}
{-# LANGUAGE OverloadedStrings #-}

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
  Credentials (..), Client, Temporary, Token,

  -- 'Temporary' and 'Token' credentials specialize 'Client'
  -- credentials and thus instantiate the 'HasToken' class.
  HasToken,

  -- * Component Access
  clientKey, clientSecret, tokenKey, tokenSecret, clientComponent,

  -- ** Basic
  viewClientKey, viewClientSecret, viewTokenKey, viewTokenSecret,

  -- * Building and upgrading credentials
  clientCredentials, temporaryCredentials, tokenCredentials,

  -- * Signing
  signingKey

  ) where

import           Control.Applicative
import qualified Data.ByteString                 as S
import qualified Data.ByteString.Char8           as S8
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

-- | 'Token' 'Credentials' are credentials which provide a client
-- access to a user's protected resource *semi-permanently*.
data Token

-- | Credentials are created at various points during the OAuth
-- handshakes. Each time they are a pair of a key and a secret, the
-- first of which being public the second private.

data Credentials ty where
  ClientCredentials
    :: S.ByteString -> S.ByteString -> Credentials Client
  TemporaryCredentials
    :: S.ByteString -> S.ByteString    -- linked client credentials
       -> S.ByteString -> S.ByteString -- temporary credentials
       -> Credentials Temporary
  TokenCredentials
    :: S.ByteString -> S.ByteString    -- linked client credentials
       -> S.ByteString -> S.ByteString -- temporary credentials
       -> Credentials Token

-- | 'Credentials' with tokens are 'Temporary' or 'Token'
-- 'Credentials'. 'Client' 'Credentials' always have empty tokens.
class HasToken c where
  tokenKey
    :: Functor f => (S.ByteString -> f S.ByteString)
       -> Credentials c -> f (Credentials c)
  tokenSecret
    :: Functor f => (S.ByteString -> f S.ByteString)
       -> Credentials c -> f (Credentials c)
  clientComponent
    :: Functor f => (Credentials Client -> f (Credentials Client))
       -> Credentials c -> f (Credentials c)

instance HasToken Temporary where
  tokenKey inj (TemporaryCredentials k s kk ss) =
    (\kk' -> TemporaryCredentials k s kk' ss) <$> inj kk
  {-# INLINE tokenKey #-}
  tokenSecret inj (TemporaryCredentials k s kk ss) =
    TemporaryCredentials k s kk <$> inj ss
  {-# INLINE tokenSecret #-}
  clientComponent inj (TemporaryCredentials k s kk ss) =
    temporaryCredentials (kk, ss) <$> inj (ClientCredentials k s)
  {-# INLINE clientComponent #-}

instance HasToken Token where
  tokenKey inj (TokenCredentials k s kk ss) =
    (\kk' -> TokenCredentials k s kk' ss) <$> inj kk
  {-# INLINE tokenKey #-}
  tokenSecret inj (TokenCredentials k s kk ss) =
    TokenCredentials k s kk <$> inj ss
  {-# INLINE tokenSecret #-}
  clientComponent inj (TokenCredentials k s kk ss) =
    tokenCredentials (kk, ss) <$> inj (ClientCredentials k s)
  {-# INLINE clientComponent #-}

-- | Lens over the 'Client' key component available in all
-- 'Credentials'.
clientKey
  :: Functor f => (S.ByteString -> f S.ByteString)
     -> Credentials ty -> f (Credentials ty)
clientKey inj (ClientCredentials k s) =
  (\k' -> ClientCredentials k' s) <$> inj k
clientKey inj (TemporaryCredentials k s kk ss) =
  (\k' -> TemporaryCredentials k' s kk ss) <$> inj k
clientKey inj (TokenCredentials k s kk ss) =
  (\k' -> TokenCredentials k' s kk ss) <$> inj k

viewClientKey :: Credentials ty -> S8.ByteString
viewClientKey = view clientKey

-- | Lens over the 'Client' key-secret component available in all
-- 'Credentials'.
clientSecret
  :: Functor f => (S.ByteString -> f S.ByteString)
     -> Credentials ty -> f (Credentials ty)
clientSecret inj (ClientCredentials k s) =
  (\s' -> ClientCredentials k s') <$> inj s
clientSecret inj (TemporaryCredentials k s kk ss) =
  (\s' -> TemporaryCredentials k s' kk ss) <$> inj s
clientSecret inj (TokenCredentials k s kk ss) =
  (\s' -> TokenCredentials k s' kk ss) <$> inj s

viewClientSecret :: Credentials ty -> S8.ByteString
viewClientSecret = view clientSecret

viewTokenKey :: Credentials ty -> S8.ByteString
viewTokenKey ClientCredentials{}         = S.empty
viewTokenKey cred@TemporaryCredentials{} = view tokenKey cred
viewTokenKey cred@TokenCredentials{}     = view tokenKey cred

viewTokenSecret :: Credentials ty -> S8.ByteString
viewTokenSecret ClientCredentials{}         = S.empty
viewTokenSecret cred@TemporaryCredentials{} = view tokenSecret cred
viewTokenSecret cred@TokenCredentials{}     = view tokenSecret cred

-- | Creates a signing key based on the kind of credentials currently
-- possessed.
signingKey :: Credentials ty -> S.ByteString
signingKey cred =
  HTTP.urlEncode True (view clientSecret cred)
  <> "&" <>
  HTTP.urlEncode True (viewTokenSecret cred)

-- | Build basic 'Client' 'Credentials' from client token and client
-- token secret componenets.
clientCredentials
  :: (S.ByteString, S.ByteString) -> Credentials Client
clientCredentials = uncurry ClientCredentials

-- | Upgrade 'Client' 'Credentials' to 'Temporary' 'Credential's by
-- adding in the temporary token and temporary token secret
-- componenets.
temporaryCredentials
  :: (S.ByteString, S.ByteString)
     -> Credentials Client -> Credentials Temporary
temporaryCredentials (tok, tokSec) (ClientCredentials k s) =
  TemporaryCredentials k s tok tokSec
{-# INLINE temporaryCredentials #-}

-- | Upgrade any set of 'Credentials' to 'Token' 'Credentials' by
-- adding in the token and token secret componenets.
tokenCredentials
  :: (S.ByteString, S.ByteString) -> Credentials ty -> Credentials Token
tokenCredentials (tok, tokSec) cred =
  TokenCredentials (view clientKey cred) (view clientSecret cred) tok tokSec
{-# INLINE tokenCredentials #-}

instance Show (Credentials Client) where
  show c = "Credentials [Client] { credClientKey = "
           ++ view (clientKey . to show) c
           ++ " }"

instance Show (Credentials Temporary) where
  show cred =
    "Credentials [Temporary] { credClientKey = "
    ++ view (clientKey . to show) cred
    ++ ", temporaryKey = "
    ++ view (tokenKey . to show) cred
    ++ " }"

instance Show (Credentials Token) where
  show cred =
    "Credentials [Token] { credClientKey = "
    ++ view (clientKey . to show) cred
    ++ ", tokenKey = "
    ++ view (tokenKey . to show) cred
    ++ " }"
