{-# LANGUAGE RecordWildCards #-}

module SigningSpec where

import Control.Monad
import Network.HTTP.Client (httpLbs, parseRequest, responseStatus)
import Network.HTTP.Types (status200)
import Network.OAuth (oauth)
import Test.Hspec (Spec, describe, example, it)
import Test.Hspec.Expectations (shouldBe)

import Config (Config (Config, cred, man, rng, ser, url))

spec :: Config -> Spec
spec Config {..} = describe "signing" $ do
  it "authorizes a request" $ do
    req <- parseRequest url
    (signedReq, _) <- oauth cred ser req rng
    resp <- httpLbs signedReq man
    responseStatus resp `shouldBe` status200

  it "authorizes many requests" $ do
    req <- parseRequest url
    (_, resps) <- foldM (\ (gen, acc) next -> do
                            (signedReq, newGen) <- oauth cred ser next gen
                            resp <- httpLbs signedReq man
                            pure (newGen, resp:acc)
                        ) (rng, []) (replicate 100 req)
    forM_ resps $ \ resp ->
      example $ responseStatus resp `shouldBe` status200
