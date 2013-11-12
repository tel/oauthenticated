{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.HTTP.Conduit.OAuth.Types.Basic
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.HTTP.Conduit.OAuth.Types.Basic where

import           Control.Monad.Identity
import qualified Data.CaseInsensitive                       as CI
import qualified Network.HTTP.Conduit                       as Client
import           Network.HTTP.Conduit.OAuth.Internal.ToHTTP

-- | While "Network.HTTP.Conduit" generally allows the request body to
-- be generated incrementally in any 'Monad', we need to be able to
-- view the entire body at once and thus cannot take advantage of
-- streaming. Thus, we need only a simplified 'Client.Request'.

type Request = Client.Request Identity

-- | The OAuth spec suggest that the OAuth parameter be passed via the
-- @Authorization@ header, but allows for other methods of
-- transmission (see section "3.5. Parameter Transmission") so we
-- select the 'Server'\'s preferred method with this type.
data ParameterMethod = AuthorizationHeader
                     | RequestEntityBody
                     | QueryString
                       deriving ( Show, Eq, Ord )

-- | How the OAuth request be cryptographically signed. If 'Plaintext'
-- is used then the request should be conducted over a secure
-- transport layer like TLS.
data SignatureMethod = HmacSha1
                     deriving ( Show, Eq, Ord )

instance ToHTTP SignatureMethod where
  toHTTP HmacSha1  = "HMAC-SHA1"

instance FromHTTP SignatureMethod where
  fromHTTP s = case CI.mk s of
    ci | ci == "hmac-sha1" -> Just HmacSha1
       | otherwise         -> Nothing

data Version = OAuth1 deriving ( Show, Eq, Ord )

instance ToHTTP Version where
  toHTTP OAuth1 = "1.0"

instance FromHTTP Version where
  fromHTTP "1.0" = Just OAuth1
  fromHTTP _     = Nothing
