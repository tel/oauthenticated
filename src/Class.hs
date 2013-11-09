
module Class where

import qualified Data.Attoparsec.Char8 as At
import qualified Data.ByteString       as S
import qualified Data.ByteString.Char8 as S8
import           Data.Time
import           Data.Time.Clock.POSIX

-- | Serialization over the wire
class ToHTTP a where
  toHTTP :: a -> S.ByteString

class FromHTTP a where
  fromHTTP :: S.ByteString -> Maybe a

instance ToHTTP Integer where
  toHTTP = S8.pack . show

instance FromHTTP Integer where
  fromHTTP = either (const Nothing) Just . At.parseOnly At.decimal

instance ToHTTP UTCTime where
  toHTTP = toHTTP . flip asTypeOf (3 :: Integer) . round . utcTimeToPOSIXSeconds

instance FromHTTP UTCTime where
  fromHTTP = fmap (posixSecondsToUTCTime . fromIntegral)
             . (fromHTTP :: S.ByteString -> Maybe Integer)
