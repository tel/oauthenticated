-- |
-- Module      : Network.OAuth.Util
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.OAuth.Util where

import qualified Data.ByteString    as S
import           Network.HTTP.Types (urlEncode)

pctEncode :: S.ByteString -> S.ByteString
pctEncode = urlEncode True
