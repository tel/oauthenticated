{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Network.HTTP.Conduit.OAuth.Types.Callback
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.HTTP.Conduit.OAuth.Types.Callback (

  -- * Callback types
  Callback (..), _OutOfBand, _Callback,

  -- ** Building from Strings
  parseCallback

  ) where

import           Control.Applicative
import           Control.Monad
import qualified Data.ByteString.Char8                      as S8
import qualified Data.CaseInsensitive                       as CI
import           Data.Profunctor
import qualified Network.HTTP.Conduit                       as Client
import qualified Network.HTTP.Conduit.Internal              as Client
import           Network.HTTP.Conduit.OAuth.Internal.ToHTTP
import           Network.HTTP.Conduit.OAuth.Types.Basic
import           Network.HTTP.Conduit.OAuth.Util
import qualified Network.HTTP.Types                         as HTTP

-- Callbacks
--------------------------------------------------------------------------------

-- | Clients MUST provide callback URLs to the Server or the string
-- \"oob\" indicating out-of-band authorization will occur.
data Callback = Callback Request | OutOfBand
                deriving ( Show )

_OutOfBand ::
  (Choice p, Applicative f) =>
  p () (f ()) -> p Callback (f Callback)
_OutOfBand = prism (const OutOfBand) $ \it -> case it of
  OutOfBand -> Right ()
  els       -> Left els
{-# INLINE _OutOfBand #-}

_Callback ::
  (Choice p, Applicative f) =>
  p Request (f Request) -> p Callback (f Callback)
_Callback = prism Callback $ \it -> case it of
  Callback cb -> Right cb
  els         -> Left els
{-# INLINE _Callback #-}

instance ToHTTP Callback where
  toHTTP (Callback req) = HTTP.urlEncode True . S8.pack . show . Client.getUri $ req
  toHTTP OutOfBand      = "oob"

instance FromHTTP Callback where
  fromHTTP s = case CI.mk s of
    ci | ci == "oob" -> Just OutOfBand
       | otherwise   -> Callback <$> Client.parseUrl (S8.unpack s)

-- | Tries to create a 'Callback' from a 'String' representation. This
-- can fail if the 'String' is not a proper URL.
parseCallback :: String -> Maybe Callback
parseCallback = liftM Callback . Client.parseUrl
