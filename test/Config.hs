{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Config where

import Crypto.Random (SystemRNG, cprgCreate, createEntropyPool)
import Network.HTTP.Client (Manager, newManager)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.OAuth (Client, Cred, Server, Token (Token), clientCred, defaultServer)

data Config = Config
  { rng  :: SystemRNG
  , man  :: Manager
  , ser  :: Server
  , cred :: Cred Client
  , url  :: String
  }

loadConfig :: IO Config
loadConfig = do
  -- these are on the public internet so they're okay
  let cred = clientCred $ Token "RKCGzna7bv9YD57c" "D+EdQ-gs$-%@2Nu7"
      url = "https://postman-echo.com/oauth1"
      ser = defaultServer
  rng <- cprgCreate <$> createEntropyPool
  man <- newManager tlsManagerSettings
  pure $ Config {..}
