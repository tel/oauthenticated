#! /usr/bin/env stack
{- stack --resolver lts-10.4 --install-ghc runghc --package classy-prelude --package http-client --package crypto-random --package oauthenticated --package uri-templater -}
{-# OPTIONS_GHC -Wall -Werror           #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NoImplicitPrelude          #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE PackageImports             #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE TypeOperators              #-}

import ClassyPrelude
import qualified "crypto-random" Crypto.Random as Crypto
import Data.Aeson (FromJSON, Value, eitherDecodeStrict')
import qualified Data.ByteString.Char8 as Char8
import qualified Network.HTTP.Client as Client
import qualified Network.OAuth as OAuth
import qualified Options.Applicative as Opt

data Opts = Opts
  { oauthUrl    :: String
  , oauthKey    :: ByteString
  , oauthSecret :: ByteString
  }

data App = App
  { appRng     :: TVar Crypto.SystemRNG
  , appManager :: Client.Manager
  , appServer  :: OAuth.Server
  , appCred    :: OAuth.Cred OAuth.Client
  }

makeRequest :: FromJSON a => App -> Client.Request -> IO a
makeRequest App {..} req = do
  rng <- readTVarIO appRng
  (signedReq, newRng) <- OAuth.oauth appCred appServer req rng
  atomically $ writeTVar appRng newRng
  putStrLn $ tshow signedReq
  resp <- Client.httpLbs signedReq appManager
  putStrLn $ tshow resp
  either (\ msg -> fail $ "Couldn't decode " <> show resp <> " due to " <> msg) pure $
    eitherDecodeStrict' (toStrict $ Client.responseBody resp)

parseArgs :: IO Opts
parseArgs =
  let parser = Opts
        <$> Opt.strOption (Opt.long "oauth-url" <> Opt.help "URL")
        <*> (Char8.pack <$> Opt.strOption (Opt.long "oauth-key" <> Opt.help "Consumer key"))
        <*> (Char8.pack <$> Opt.strOption (Opt.long "oauth-secret" <> Opt.help "Consumer secret"))
  in Opt.execParser $ Opt.info (Opt.helper <*> parser) (Opt.fullDesc <> Opt.progDesc "Send a test OAuth 1.0a request to a URL")

main :: IO ()
main = do
  Opts {..} <- parseArgs
  req <- Client.parseRequest oauthUrl
  rng <- Crypto.cprgCreate <$> Crypto.createEntropyPool
  rngTv <- newTVarIO rng
  manager <- Client.newManager Client.defaultManagerSettings
  let cred = OAuth.clientCred $ OAuth.Token oauthKey oauthSecret
      app = App rngTv manager OAuth.defaultServer cred
  _ :: Value <- makeRequest app req
  pure ()
