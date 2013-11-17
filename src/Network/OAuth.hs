-- |
-- Module      : Network.OAuth
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--

module Network.OAuth where

import           Control.Applicative
import           Control.Monad.State
import           Crypto.Random
import           Network.HTTP.Client.Manager     (Manager)
import           Network.HTTP.Client.Types       (Request)
import           Network.OAuth.MuLens
import           Network.OAuth.Signing           (sign)
import           Network.OAuth.Stateful
import           Network.OAuth.Types.Credentials (Client, Cred, Permanent,
                                                  Temporary, Token, key, secret)
import           Network.OAuth.Types.Params      (ParameterMethod (..),
                                                  Server (..),
                                                  SignatureMethod (..),
                                                  Workflow (..))
import qualified Network.OAuth.Types.Params      as P


