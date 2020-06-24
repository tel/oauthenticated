{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TupleSections     #-}

-- |
-- Module      : Network.OAuth.Signing
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Signing forms the core process for OAuth. Given a 'C.Request' about to be
-- sent, 'Server' parameters, and a full 'Oa' we append a set of parameters to
-- the 'C.Request' which turns it into a signed OAuth request.

module Network.OAuth.Signing (

  -- * Primary interface

  -- | The 'oauth' and 'sign' commands can be used as low level signing
  -- primitives, and they are indeed used to build the "Network.OAuth.Stateful"
  -- interface exported by default.

  oauth, sign,

  -- * Low-level interface

  -- | The low-level interface is used to build 'oauth' and 'sign' and can be
  -- useful for testing.

  makeSignature, augmentRequest, canonicalBaseString, canonicalParams,
  oauthParams, canonicalUri, bodyParams, queryParams

  ) where

import qualified Blaze.ByteString.Builder        as Blz
import           Control.Monad.IO.Class          (MonadIO)
import           Crypto.Hash                     (SHA1, SHA256)
import           Crypto.Random                   (MonadRandom)
import           Crypto.MAC.HMAC                 (HMAC, hmac)
import           Data.ByteArray                  (convert)
import qualified Data.ByteString                 as S
import qualified Data.ByteString.Base64          as S64
import qualified Data.ByteString.Char8           as S8
import qualified Data.ByteString.Lazy            as SL
import           Data.Char                       (toUpper)
import           Data.List                       (sort)
import           Data.Maybe                      (fromMaybe, mapMaybe)
import           Data.Monoid
import qualified Network.HTTP.Client             as C
import qualified Network.HTTP.Types              as H
import qualified Network.HTTP.Types.QueryLike    as H
import           Network.OAuth.MuLens
import           Network.OAuth.Types.Credentials
import           Network.OAuth.Types.Params
import           Network.OAuth.Util
import           Network.URI

-- | Sign a request with a fresh set of parameters.
oauth :: (MonadIO m, MonadRandom m) => Cred ty -> Server -> C.Request -> m C.Request
oauth creds sv req = do
  oax <- freshOa creds
  return $ sign oax sv req

-- | Sign a request given generated parameters
sign :: Oa ty -> Server -> C.Request -> C.Request
sign oax server req =
  let payload = canonicalBaseString oax server req
      sigKey  = signingKey (credentials oax)
      sig     = makeSignature (signatureMethod server) sigKey payload
      params  = ("oauth_signature", H.toQueryValue sig) : oauthParams oax server
  in augmentRequest (parameterMethod server) params req

makeSignature :: SignatureMethod -> S.ByteString -> S.ByteString -> S.ByteString
makeSignature HmacSha1    sigKey payload = S64.encode $ convert (hmac sigKey payload :: HMAC SHA1)
makeSignature HmacSha256  sigKey payload = S64.encode $ convert (hmac sigKey payload :: HMAC SHA256)
makeSignature Plaintext   sigKey _       = sigKey

-- | Augments whatever component of the 'C.Request' is specified by
-- 'ParameterMethod' with one built from the apropriate OAuth parameters
-- (passed as a 'H.Query').
--
-- Currently this actually /replaces/ the @Authorization@ header if one
-- exists. This may be a bad idea if the @realm@ parameter is pre-set,
-- perhaps.
--
-- TODO: Parse @Authorization@ header and augment it.
--
-- Currently this actually /replaces/ the entity body if one
-- exists. This is definitely just me being lazy.
--
-- TODO: Try to parse entity body and augment it.
augmentRequest :: ParameterMethod -> H.Query -> C.Request -> C.Request
augmentRequest AuthorizationHeader q req =
  let replaceHeader :: H.HeaderName -> S.ByteString -> H.RequestHeaders -> H.RequestHeaders
      replaceHeader n b [] = [(n, b)]
      replaceHeader n b (x@(hn, _):rest) | n == hn   = (n, b):rest
                 | otherwise = x : replaceHeader n b rest
      authHeader = "OAuth " <> S8.intercalate ", " pairs
      pairs = map mkPair q
      -- We should perhaps pctEncode the key in each pair as well, but so
      -- long as this is a well-formed OAuth header the keys will never
      -- require encoding.
      mkPair (k, v) = k <> "=\"" <> pctEncode (fromMaybe "" v) <> "\""
  in req { C.requestHeaders = replaceHeader H.hAuthorization authHeader (C.requestHeaders req) }
augmentRequest QueryString q req =
  let q0 = H.parseQuery (C.queryString req)
  in  req { C.queryString = H.renderQuery True (q ++ q0) }
augmentRequest RequestEntityBody q req =
  let fixQ = mapMaybe (\(a, mayB) -> (a,) <$> mayB) q
  in  C.urlEncodedBody fixQ req

canonicalBaseString :: Oa ty -> Server -> C.Request -> S.ByteString
canonicalBaseString oax server req =
  S8.intercalate "&" [ S8.map toUpper (C.method req)
                     , canonicalUri req
                     , canonicalParams oax server req
                     ]

canonicalParams :: Oa ty -> Server -> C.Request -> S.ByteString
canonicalParams oax server req =
  let build :: H.QueryItem -> S.ByteString
      build (k, mayV) = pctEncode k <> maybe S.empty (\v -> "=" <> pctEncode v) mayV

      combine :: [S.ByteString] -> S.ByteString
      combine = pctEncode . S8.intercalate "&"

      reqIsFormUrlEncoded = case lookup H.hContentType (C.requestHeaders req) of
                              Just "application/x-www-form-urlencoded" -> True
                              _                                        -> False
  in combine . sort . map build . mconcat
     $ [ oauthParams oax server
       , if reqIsFormUrlEncoded then bodyParams req else []
       , queryParams req
       ]

oauthParams :: Oa ty -> Server -> H.Query
oauthParams (Oa {..}) (Server {..}) =
  let

    OaPin {..} = pin

    infix 8 -:
    s -: v = (s, H.toQueryValue v)

    -- **NOTE** dfithian: It worked for my use case to move oauth_token into these params. From the
    -- PR:
    --
    -- I presume one very controversial thing I did was to move `oauth_token` into `workflowParams`.
    -- I came to this conclusion by skimming through the [RFC](https://tools.ietf.org/html/rfc5849)
    -- and deciding that since I only ever saw `oauth_token` in conjunction with either
    -- `oauth_callback` or `oauth_verifier` that they should go together. I'd be perfectly happy to
    -- instead pass in some function of the settings telling it whether or not to include
    -- `oauth_token` for a given request. Whatever the conclusion, the service I'm integrating to
    -- specifically does NOT want the `oauth_token` so that was the motivation.
    workflowParams Standard = []
    workflowParams (TemporaryTokenRequest callback) =
      [ "oauth_callback" -: callback
      , "oauth_token" -: (getResourceTokenDef credentials ^. key) ]
    workflowParams (PermanentTokenRequest verifier) =
      [ "oauth_verifier" -: verifier
      , "oauth_token" -: (getResourceTokenDef credentials ^. key) ]

  in

    [ "oauth_version"          -: oAuthVersion
    , "oauth_consumer_key"     -: (credentials ^. clientToken . key)
    , "oauth_signature_method" -: signatureMethod
    , "oauth_timestamp"        -: timestamp
    , "oauth_nonce"            -: nonce
    ] ++ workflowParams workflow

canonicalUri :: C.Request -> S.ByteString
canonicalUri req =
  pctEncode $ S8.pack $ uriScheme <> "//" <> fauthority uriAuthority <> uriPath
  where
    URI {..} = C.getUri req
    fauthority Nothing               = ""
    fauthority (Just (URIAuth {..})) =
      let -- Canonical URIs do not display their port unless it is non-standard
          fport | (uriPort == ":443") && (uriScheme == "https:") = ""
                | (uriPort == ":80" ) && (uriScheme == "http:" ) = ""
                | otherwise                                      = uriPort
      in  uriRegName <> fport

-- | Queries a 'C.Request' body and tries to interpret it as a set of OAuth
-- valid parameters. It makes the assumption that if the body type is a
-- streaming variety or impure then it is /not/ a set of OAuth parameters---
-- dropping this assumption would prevent this from being pure.
bodyParams :: C.Request -> H.Query
bodyParams = digestBody . C.requestBody where
  digestBody :: C.RequestBody -> H.Query
  digestBody (C.RequestBodyLBS lbs) = H.parseQuery (SL.toStrict lbs)
  digestBody (C.RequestBodyBS   bs) = H.parseQuery bs
  digestBody (C.RequestBodyBuilder _ b) = H.parseQuery (Blz.toByteString b)
  digestBody (C.RequestBodyStream  _ _) = []
  digestBody (C.RequestBodyStreamChunked _) = []
  digestBody (C.RequestBodyIO _) = []

  -- digestBody (Left (_, builder)) = H.parseQuery (Blz.toByteString builder)
  -- digestBody (Right _) = []

queryParams :: C.Request -> H.Query
queryParams = H.parseQuery . C.queryString
