{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings  #-}

-- |
-- Module      : Network.OAuth.Types.Params
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- /OAuth Parameters/
--
-- OAuth 1.0 operates by creating a set of \"oauth parameters\" here
-- called 'Oa' which augment a request with OAuth specific
-- metadata. They may be used to augment the request by one of several
-- 'ParameterMethods'.

module Network.OAuth.Types.Params where

import           Crypto.Random
import qualified Data.ByteString                 as S
import qualified Data.ByteString.Base16          as S16
import           Data.Data
import           Data.Time
import           Network.HTTP.Client.Types       (Request)
import           Network.OAuth.Types.Credentials

-- Basics
--------------------------------------------------------------------------------

-- | The OAuth spec suggest that the OAuth parameter be passed via the
-- @Authorization@ header, but allows for other methods of
-- transmission (see section "3.5. Parameter Transmission") so we
-- select the 'Server'\'s preferred method with this type.
data ParameterMethod = AuthorizationHeader
                       -- ^ Place the 'Oa' parameters in the
                       -- @Authorization@ HTTP header.
                     | RequestEntityBody
                       -- ^ Augment the @www-form-urlencoded@ request
                       -- body with 'Oa' parameters.
                     | QueryString
                       -- ^ Augment the @www-form-urlencoded@ query
                       -- string with 'Oa' parameters.
                       deriving ( Show, Eq, Ord, Data, Typeable )

-- | OAuth culminates in the creation of the @oauth_signature@ which
-- signs and authenticates the request using the secret components of
-- a particular OAuth 'Network.OAuth.Types.Credentials.Cred'.
--
-- Several methods exist for generating these signatures, the most
-- popular being 'HmacSha1'.
data SignatureMethod = HmacSha1
                     | Plaintext
                     deriving ( Show, Eq, Ord, Data, Typeable )

-- | OAuth is a family of request signature methods, indexed by
-- 'Version's.
data Version = OAuth1 deriving ( Show, Eq, Ord, Data, Typeable )


-- | When performing the second leg of the three-leg token request workflow,
-- the user must pass the @oauth_verifier@ code back to the client. In order to
-- ensure that this protocol is secure, OAuth demands that the client
-- associates this \"callback method\" with the temporary credentials generated
-- for the workflow. This 'Callback' method may be a URL where the parameters
-- are returned to or the string @\"oob\"@ which indicates that the user is
-- responsible for returning the @oauth_verifier@ to the client 'OutOfBand'.
data Callback = OutOfBand | Callback Request
  deriving ( Show, Typeable )

-- Server information
--------------------------------------------------------------------------------

-- | The 'Server' information contains details which parameterize how a
-- particular server wants to interpret OAuth requests.
data Server =
  Server { parameterMethod :: ParameterMethod
         , signatureMethod :: SignatureMethod
         , oAuthVersion    :: Version
         } deriving ( Show, Eq, Ord, Data, Typeable )

-- | The default 'Server' parameterization uses OAuth recommended parameters.
defaultServer :: Server
defaultServer = Server AuthorizationHeader HmacSha1 OAuth1

-- Params
--------------------------------------------------------------------------------

-- | Some special OAuth requests use extra @oauth_*@ parameters. For example,
-- when requesting a temporary credential, it's necessary that a
-- @oauth_callback@ parameter be specified. 'WorkflowParams' allows these extra
-- parameters to be specified.
data Workflow = Standard
                -- ^ No special OAuth parameters needed
              | TemporaryTokenRequest Callback
              | PermanentTokenRequest S.ByteString
                -- ^ Includes the @oauth_verifier@
  deriving ( Show, Typeable )

-- | The 'OaPin' is a set of impure OAuth parameters which are generated for each
-- request in order to ensure uniqueness and temporality.
data OaPin =
  OaPin { timestamp :: UTCTime
        , nonce     :: S.ByteString
        } deriving ( Show, Eq, Ord, Data, Typeable )

-- | An \"empty\" pin useful for testing. This 'OaPin' is referentially
-- transparent and thus has none of the necessary security features---it should
-- /never/ be used in an actual transaction!
emptyPin :: OaPin
emptyPin = OaPin { timestamp = UTCTime (ModifiedJulianDay 0) 0
                 , nonce     = "\0\0\0\0\0"
                 }

-- | Creates a new, unique, unpredictable 'OaPin'. This should be used quickly
-- as dependent on the OAuth server settings it may expire.
freshPin :: CPRG gen => gen -> IO (OaPin, gen)
freshPin gen = do
  t <- getCurrentTime
  return (OaPin { timestamp = t, nonce = n }, gen')
  where
    (n, gen') = withRandomBytes gen 8 S16.encode

-- | The 'Oa' parameters include all the OAuth information specific to a single
-- request. They are not sufficient information by themselves to generate the
-- entire OAuth request but instead must be augmented with 'Server' information.
data Oa ty =
  Oa { credentials :: Cred ty
     , workflow    :: Workflow
     , pin         :: OaPin
     }
