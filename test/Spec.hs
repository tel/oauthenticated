import Test.Hspec (hspec)

import Config (loadConfig)
import qualified SigningSpec

main :: IO ()
main = do
  config <- loadConfig
  hspec $ do
    SigningSpec.spec config
