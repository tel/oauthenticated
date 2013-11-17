{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings  #-}

-- |
-- Module      : Network.OAuth.Type.Credentials
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.OAuth.Types.Credentials (
  -- * Basic credential types
  Token (..), Cred (..), Key, Secret, Client, Temporary, Permanent,
  -- ** Constructors
  clientCred, temporaryCred, permanentCred, fromUrlEncoded,
  -- * Accessors
  key, secret, clientToken, resourceToken, signingKey
  ) where

import           Control.Applicative
import           Control.Monad
import           Data.Aeson
import qualified Data.ByteString      as S
import           Data.Data
import           Data.Monoid
import           Network.HTTP.Types   (urlEncode, parseQuery)
import           Network.OAuth.MuLens
import           Network.OAuth.Util

-- Constructors aren't exported. They're only used for derivation
-- purposes.

-- | 'Client' 'Cred'entials and 'Token's are assigned to a particular client by
-- the server and are used for all requests sent by that client. They form the
-- core component of resource specific credentials.
data Client    = Client    deriving ( Data, Typeable )

-- | 'Temporary' 'Token's and 'Cred'entials are created during authorization
-- protocols and are rarely meant to be kept for more than a few minutes.
-- Typically they are authorized to access only a very select set of server
-- resources. During \"three-legged authorization\" in OAuth 1.0 they are used
-- to generate the authorization request URI the client sends and, after that,
-- in the 'Permanent' 'Token' request.
data Temporary = Temporary deriving ( Data, Typeable )

-- | 'Permanent' 'Token's and 'Cred'entials are the primary means of accessing
-- server resources. They must be maintained by the client for each user who
-- authorizes that client to access resources on their behalf.
data Permanent = Permanent deriving ( Data, Typeable )

-- | 'Token' 'Key's are public keys which allow a server to uniquely identify a
-- particular 'Token'.
type Key    = S.ByteString

-- | 'Token' 'Secret's are private keys which the 'Token' uses for
-- cryptographic purposes.
type Secret = S.ByteString

-- | 'Token's are public, private key pairs and come in many varieties,
-- 'Client', 'Temporary', and 'Permanent'.
data Token ty = Token {-# UNPACK #-} !Key
                      {-# UNPACK #-} !Secret
  deriving ( Show, Eq, Ord, Data, Typeable )

-- | Parses a JSON object with keys @oauth_token@ and @oauth_token_secret@, the
-- standard format for OAuth 1.0.
instance FromJSON (Token ty) where
  parseJSON = withObject "OAuth Token" $ \o ->
    Token <$> o .: "oauth_token"
          <*> o .: "oauth_token_secret"

-- | Produces a JSON object using keys named @oauth_token@ and
-- @oauth_token_secret@.
instance ToJSON (Token ty) where
  toJSON (Token k s) = object [ "oauth_token"        .= k
                              , "oauth_token_secret" .= s
                              ]

fromUrlEncoded :: S.ByteString -> Maybe (Token ty)
fromUrlEncoded = tryParse . parseQuery where
  tryParse q = Token <$> lookupV "oauth_token"        q
                     <*> lookupV "oauth_token_secret" q
  lookupV k = join . lookup k

key :: Lens (Token ty) (Token ty) Key Key
key inj (Token k s) = (`Token` s) <$> inj k
{-# INLINE key #-}

secret :: Lens (Token ty) (Token ty) Secret Secret
secret inj (Token k s) = Token k <$> inj s
{-# INLINE secret #-}

-- | 'Cred'entials pair a 'Client' 'Token' and either a 'Temporary' or
-- 'Permanent' token corresponding to a particular set of user
-- resources on the server.
data Cred ty = Cred         {-# UNPACK #-} !Key {-# UNPACK #-} !Secret
             | CredAndToken {-# UNPACK #-} !Key {-# UNPACK #-} !Secret {-# UNPACK #-} !(Token ty)
  deriving ( Show, Eq, Ord, Data, Typeable )

clientToken :: Lens (Cred ty) (Cred ty) (Token Client) (Token Client)
clientToken inj (Cred k s) = fixUp <$> inj (Token k s) where
  fixUp (Token k' s') = Cred k' s'
clientToken inj (CredAndToken k s tok) = fixUp <$> inj (Token k s) where
  fixUp (Token k' s') = CredAndToken k' s' tok
{-# INLINE clientToken #-}

resourceToken :: Lens (Cred ty) (Cred ty') (Maybe (Token ty)) (Maybe (Token ty'))
resourceToken inj c = case c of 
  Cred         k s     -> build k s <$> inj Nothing
  CredAndToken k s tok -> build k s <$> inj (Just tok)
  where
    build k s Nothing    = Cred k s
    build k s (Just tok) = CredAndToken k s tok
{-# INLINE resourceToken #-}

clientCred :: Token Client -> Cred Client
clientCred (Token k s) = Cred k s

temporaryCred :: Token Temporary -> Cred Client -> Cred Temporary
temporaryCred tok (Cred         k s  ) = CredAndToken k s tok
temporaryCred tok (CredAndToken k s _) = CredAndToken k s tok

permanentCred :: Token Permanent -> Cred Client -> Cred Permanent
permanentCred tok (Cred         k s  ) = CredAndToken k s tok
permanentCred tok (CredAndToken k s _) = CredAndToken k s tok

-- | Produce a 'signingKey' from a set of credentials. This is a URL
-- encoded string built from the client secret and the token
-- secret. If no token secret exists then the blank string is used.
signingKey :: Cred ty -> S.ByteString
signingKey (Cred _ clSec) = urlEncode True clSec <> "&" <> ""
signingKey (CredAndToken _ clSec (Token _ tkSec)) =
  pctEncode clSec <> "&" <> pctEncode tkSec
