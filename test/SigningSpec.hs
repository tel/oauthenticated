{-# LANGUAGE RecordWildCards #-}

module SigningSpec where

import Control.Monad
import Network.HTTP.Client (httpLbs, parseRequest, responseStatus)
import Network.HTTP.Types (status200)
import Network.OAuth (oauth)
import Test.Hspec (Spec, describe, example, it)
import Test.Hspec.Expectations (shouldBe)

import Config (Config (Config, cred, man, ser, url))

spec :: Config -> Spec
spec Config {..} = describe "signing" $ do
  it "authorizes a request" $ do
    req <- parseRequest url
    signedReq <- oauth cred ser req
    resp <- httpLbs signedReq man
    responseStatus resp `shouldBe` status200

  it "authorizes many requests" $ do
    req <- parseRequest url
    resps <- foldM (\ acc next -> do
                            signedReq <- oauth cred ser next
                            resp <- httpLbs signedReq man
                            pure $ resp:acc
                        ) [] (replicate 100 req)
    forM_ resps $ \ resp ->
      example $ responseStatus resp `shouldBe` status200
