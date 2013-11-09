{-# LANGUAGE OverloadedStrings #-}

-- | Finalizing 'Client.Request's using 'Oa' parameters
module Signing where

import qualified Blaze.ByteString.Builder  as Blaze
import           Control.Applicative
import           Control.Arrow
import           Control.Monad.Identity
import           Crypto.Hash.SHA1          (hash)
import           Crypto.MAC.HMAC           (hmac)
import qualified Data.ByteString           as S
import qualified Data.ByteString.Base64    as S64
import qualified Data.ByteString.Char8     as S8
import qualified Data.ByteString.Lazy      as SL
import           Data.Char                 (toUpper)
import           Data.Conduit
import qualified Data.Conduit.List         as Conduit
import           Data.List                 (sort)
import           Data.Monoid
import qualified Network.HTTP.Conduit      as Client
import qualified Network.HTTP.Types.Header as HTTP
import qualified Network.HTTP.Types.URI    as HTTP

import           Data.Maybe
import           Types

sign :: Credentials ty -> Server -> Oa ty -> Client.Request Identity -> Client.Request Identity
sign creds srv oax req0 =
  let base = buildBaseString req0 oax
      key  = credSigningKey creds
      sig  = S64.encode (hmac hash 64 key base)
      oax' = oax { oaSignature = Just sig }
  in augmentRequest srv oax' req0

-- | Build the proper 'Oa' parameters into a 'Client.Request' and sign
-- it. All of the necessary request parameters should have been put
-- into the 'Client.Request' prior to this step as any further
-- modification of the HTTP method, URL, query string, body, or
-- @Authorization@ header will invalidate the request.
freeze :: Credentials ty -> Server
          -> Client.Request Identity -> IO (Client.Request Identity)
freeze creds srv req0  = do
  oax <- freshOa creds srv
  return (sign creds srv oax req0)


-- | Add the 'Oa' parameters to the 'Client.Request' according to the
-- 'Server'\'s convention.
augmentRequest :: Server -> Oa ty -> Client.Request Identity -> Client.Request Identity
augmentRequest srv oax req = case parameterMethod srv of
  AuthorizationHeader ->
    let
      hdrs0   = Client.requestHeaders req
      authhdr = oaToHeader Nothing oax
    in
      req { Client.requestHeaders = (HTTP.hAuthorization, authhdr) : hdrs0 }
  RequestEntityBody   ->
    let
      body0      = HTTP.parseQuery (getBody req)
      bodyparams = map (second Just) (oaToEntityBody oax)
      strong (a, mayB) = (,) <$> pure a <*> mayB
    in
     Client.urlEncodedBody (mapMaybe strong $ body0 ++ bodyparams) req
  QueryString         ->
    let
      qs0      = HTTP.parseQuery (Client.queryString req)
      qsparams = oaToQuerystring oax
    in
     req { Client.queryString = HTTP.renderQuery True (qs0 ++ qsparams) }

-- | Builds the URI without including the query string
buildUri :: Client.Request m -> S.ByteString
buildUri = pctEncode . buildUri'

-- | Builds the URI without percent encoding
buildUri' :: Client.Request m -> S.ByteString
buildUri' req = httpTyp <> Client.host req <> port <> Client.path req where
  httpTyp | Client.secure req = "https://"
          | otherwise         = "http://"
  port = let prt    = Client.port req
             prtstr = ":" <> S8.pack (show prt)
         in if Client.secure req
            then if prt == 443 then "" else prtstr
            else if prt == 80  then "" else prtstr

buildBody :: Source Identity Blaze.Builder -> S.ByteString
buildBody src =
  Blaze.toByteString (runIdentity (src $$ Conduit.fold mappend mempty))

-- | Forces the entire body so that it can be parsed for
-- parameters. This is pretty fundamentally opposed to the chunked and
-- streaming body types supported by @http-conduit@ and this is
-- indicated and enforced by the 'Identity' monad constraint.
getBody :: Client.Request Identity -> S.ByteString
getBody req = case Client.requestBody req of
  Client.RequestBodyLBS           lbs       -> SL.toStrict lbs
  Client.RequestBodyBS            bs        -> bs
  Client.RequestBodyBuilder       _ builder -> Blaze.toByteString builder
  Client.RequestBodySource        _ src     -> buildBody src
  Client.RequestBodySourceChunked chunks    -> buildBody chunks

-- | Builds the parameters list
buildParams :: Client.Request Identity -> Oa ty -> S.ByteString
buildParams req oax =
  let
    query :: HTTP.Query
    query = HTTP.parseQuery (Client.queryString req)
    body :: HTTP.Query
    body  = HTTP.parseQuery (getBody req)
    oauth :: HTTP.Query
    oauth = oaToQuerystring oax

    build :: HTTP.QueryItem -> S.ByteString
    build (k, mayV) =
      pctEncode k <> maybe S.empty (\v -> "=" <> pctEncode v) mayV

    combine :: [S.ByteString] -> S.ByteString
    combine = pctEncode . S8.intercalate "&"
  in
   combine . sort . map build $ (query ++ body ++ oauth)

-- | Gathers the components of the signing base string and properly
-- encodes and combines them.
buildBaseString :: Client.Request Identity -> Oa ty -> S.ByteString
buildBaseString req oax =
  S8.intercalate "&" [ S8.map toUpper (Client.method req)
                     , buildUri req
                     , buildParams req oax
                     ]

pctEncode :: S.ByteString -> S.ByteString
pctEncode = HTTP.urlEncode True
