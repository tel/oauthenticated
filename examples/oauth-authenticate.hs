#! /usr/bin/env stack
{- stack --resolver lts-10.4 --install-ghc runghc --package classy-prelude --package http-client --package crypto-random --package oauthenticated --package uri-templater -}
{-# OPTIONS_GHC -Wall -Werror           #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
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
import Control.Monad.RWS (MonadRWS, evalRWST, get, put)
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
  { appManager :: Client.Manager
  , appServer  :: OAuth.Server
  , appCred    :: OAuth.Cred OAuth.Client
  }

-- |Update MonadRWS state
underRWS :: MonadRWS r w s m => (r -> s -> m (a, s)) -> m a
underRWS f = do
  r <- ask
  s <- get
  (x, newS) <- f r s
  put newS
  pure x

-- |Sign a request. Obviously not super safe since it operates in State monad and operations are not
-- atomic.
signRequest :: (MonadIO m, MonadRWS App () Crypto.SystemRNG m)
  => Client.Request -> m Client.Request
signRequest req = underRWS $ \ App {..} rng ->
  liftIO $ OAuth.oauth appCred appServer req rng

makeRequest :: (FromJSON a, MonadIO m, MonadRWS App () Crypto.SystemRNG m)
  => Client.Request -> m a
makeRequest req = do
  App {..} <- ask
  liftIO $ do
    putStrLn $ tshow req
    resp <- Client.httpLbs req appManager
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
  manager <- Client.newManager Client.defaultManagerSettings
  let cred = OAuth.clientCred $ OAuth.Token oauthKey oauthSecret
      app = App manager OAuth.defaultServer cred
  _ :: Value <- fst <$> evalRWST (makeRequest =<< signRequest req) app rng
  pure ()
