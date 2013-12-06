{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}
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
-- Credentials, 'Cred's, are built from 'Token's, public/private key pairs, and
-- come in 3 varieties.
--
-- - 'Client': Represents a particular client or consumer, used as part of
-- every transaction that client signs.
--
-- - 'Temporary': Resource token representing a short-lived grant to access a
-- restricted set of server resources on behalf of the user. Typically used as
-- part of a authorization negotiation protocol.
--
-- - 'Permanent': Resource token representing a long-lived grant to access an
-- authorized set of server resources on behalf of the user. Outside of access
-- negotiation this is the most common kind of resource 'Token'.

-- 'Token's are constructed freely from public/private pairs and have
-- 'FromJSON' instances for easy retreival. 'Cred's are more strictly
-- controlled and must be constructed out of a 'Client' 'Token' and
-- (optionally) some kind of resource 'Token'.

module Network.OAuth.Types.Credentials (
  -- * Tokens and their parameterization
  Token (..), Key, Secret, Client, Temporary, Permanent, ResourceToken,

  -- ** Deserialization
  fromUrlEncoded,

  -- * Credentials and credential construction
  Cred, clientCred, temporaryCred, permanentCred, upgradeCred,

  -- * Accessors
  key, secret, clientToken, resourceToken, getResourceTokenDef, signingKey
  ) where

import           Control.Applicative
import           Control.Monad
import           Data.Aeson
import qualified Data.ByteString      as S
import           Data.Data
import           Data.Monoid
import           Network.HTTP.Types   (parseQuery, urlEncode)
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

class ResourceToken tk where
  upgradeCred' :: Token tk -> Cred tk' -> Cred tk
  upgradeCred' tok (Cred         k s  ) = CredAndToken k s tok
  upgradeCred' tok (CredAndToken k s _) = CredAndToken k s tok

instance ResourceToken Temporary
instance ResourceToken Permanent

upgradeCred :: ResourceToken tk => Token tk -> Cred tk' -> Cred tk
upgradeCred = upgradeCred'

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

-- | Parses a @www-form-urlencoded@ stream to produce a 'Token' if possible. 
-- The first result value is whether or not the token data is OAuth 1.0a 
-- compatible.
--
-- >>> fromUrlEncoded "oauth_token=key&oauth_token_secret=secret"
-- Just (False, Token "key" "secret")
--
-- >>> fromUrlEncoded "oauth_token=key&oauth_token_secret=secret&oauth_callback_confirmed=true"
-- Just (True, Token "key" "secret")
--
fromUrlEncoded :: S.ByteString -> Maybe (Bool, Token ty)
fromUrlEncoded = tryParse . parseQuery where
  tryParse q = do 
    tok <- Token <$> lookupV "oauth_token"        q
                 <*> lookupV "oauth_token_secret" q
    confirmed <- lookupV "oauth_callback_confirmed" q <|> pure ""
    return (confirmed == "true", tok)

  lookupV k = join . lookup k

-- | Lens on the key component of a 'Token'.
key :: Functor f => (Key -> f Key) -> Token ty -> f (Token ty)
key inj (Token k s) = (`Token` s) <$> inj k
{-# INLINE key #-}

-- | Lens on the key secret component of a 'Token'.
secret :: Functor f => (Secret -> f Secret) -> Token ty -> f (Token ty)
secret inj (Token k s) = Token k <$> inj s
{-# INLINE secret #-}

-- | 'Cred'entials pair a 'Client' 'Token' and either a 'Temporary' or
-- 'Permanent' token corresponding to a particular set of user
-- resources on the server.
data Cred ty = Cred         {-# UNPACK #-} !Key {-# UNPACK #-} !Secret
             | CredAndToken {-# UNPACK #-} !Key {-# UNPACK #-} !Secret {-# UNPACK #-} !(Token ty)
  deriving ( Show, Eq, Ord, Data, Typeable )

-- | A lens on the client 'Token' in any 'Cred'.
clientToken :: Functor f => (Token Client -> f (Token Client)) -> Cred ty -> f (Cred ty)
clientToken inj (Cred k s) = fixUp <$> inj (Token k s) where
  fixUp (Token k' s') = Cred k' s'
clientToken inj (CredAndToken k s tok) = fixUp <$> inj (Token k s) where
  fixUp (Token k' s') = CredAndToken k' s' tok
{-# INLINE clientToken #-}

-- | A lens focused on the resource 'Token' when available. The only
-- instances of 'ResourceToken' are 'Temporary' and 'Permanent'. This can
-- be used to upgrade 'Temporary' 'Cred's to 'Permanent' 'Cred's.
resourceToken
  :: (ResourceToken ty, ResourceToken ty', Functor f) =>
     (Token ty -> f (Token ty')) -> Cred ty -> f (Cred ty')
resourceToken inj (CredAndToken k s tok) = CredAndToken k s <$> inj tok
{-# INLINE resourceToken #-}

-- | OAuth assumes that, by default, any credential has a resource 'Token' that
-- is by default completely blank. In this way we can talk about the resource
-- 'Token' of even 'Client' 'Cred's.
--
-- >>> getResourceTokenDef (clientCred $ Token "key" "secret")
-- Token "" ""
getResourceTokenDef :: Cred ty -> Token ty
getResourceTokenDef Cred{}                 = Token "" ""
getResourceTokenDef (CredAndToken _ _ tok) = tok

clientCred :: Token Client -> Cred Client
clientCred (Token k s) = Cred k s

temporaryCred :: Token Temporary -> Cred Client -> Cred Temporary
temporaryCred tok (Cred         k s  ) = CredAndToken k s tok

permanentCred :: Token Permanent -> Cred Client -> Cred Permanent
permanentCred tok (Cred         k s  ) = CredAndToken k s tok

-- | Produce a 'signingKey' from a set of credentials. This is a URL
-- encoded string built from the client secret and the token
-- secret.
--
-- If no token secret exists then the blank string is used.
--
-- prop> \secret -> signingKey (clientCred $ Token "key" secret) == (pctEncode secret <> "&" <> "")
signingKey :: Cred ty -> S.ByteString
signingKey (Cred _ clSec) = urlEncode True clSec <> "&" <> ""
signingKey (CredAndToken _ clSec (Token _ tkSec)) =
  pctEncode clSec <> "&" <> pctEncode tkSec
