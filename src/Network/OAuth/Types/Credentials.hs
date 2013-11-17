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
  Token (..), Cred (..), Client, Temporary, Permanent,
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

-- Constructors aren't exported. They're only used for derivation
-- purposes.

data Client    = Client    deriving ( Data, Typeable )
data Temporary = Temporary deriving ( Data, Typeable )
data Permanent = Permanent deriving ( Data, Typeable )

-- | 'Token's are public, private pairs and come in many varieties,
-- 'Client', 'Temporary', and 'Permanent'.
data Token ty = Token {-# UNPACK #-} !S.ByteString {-# UNPACK #-} !S.ByteString
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

key :: Lens (Token ty) (Token ty) S.ByteString S.ByteString
key inj (Token k s) = (`Token` s) <$> inj k
{-# INLINE key #-}

secret :: Lens (Token ty) (Token ty) S.ByteString S.ByteString
secret inj (Token k s) = Token k <$> inj s
{-# INLINE secret #-}

-- | 'Cred'entials pair a 'Client' 'Token' and either a 'Temporary' or
-- 'Permanent' token corresponding to a particular set of user
-- resources on the server.
data Cred ty =
  Cred !S.ByteString !S.ByteString (Maybe (Token ty))
  deriving ( Show, Eq, Ord, Data, Typeable )

clientToken :: Lens (Cred ty) (Cred ty) (Token Client) (Token Client)
clientToken inj (Cred k s tok) = fixUp <$> inj (Token k s) where
  fixUp (Token k' s') = Cred k' s' tok
{-# INLINE clientToken #-}

resourceToken :: Lens (Cred ty) (Cred ty') (Maybe (Token ty)) (Maybe (Token ty'))
resourceToken inj (Cred k s mtok) = Cred k s <$> inj mtok
{-# INLINE resourceToken #-}

clientCred :: Token Client -> Cred Client
clientCred (Token k s) = Cred k s Nothing

temporaryCred :: Token Temporary -> Cred Client -> Cred Temporary
temporaryCred tok (Cred k s _) = Cred k s (Just tok)

permanentCred :: Token Permanent -> Cred Client -> Cred Permanent
permanentCred tok (Cred k s _) = Cred k s (Just tok)

-- | Produce a 'signingKey' from a set of credentials. This is a URL
-- encoded string built from the client secret and the token
-- secret. If no token secret exists then the blank string is used.
signingKey :: Cred ty -> S.ByteString
signingKey (Cred _ clSec tok) =
  urlEncode True clSec <> "&" <> case tok of
    Nothing               -> S.empty
    Just (Token _ tokSec) -> urlEncode True tokSec
