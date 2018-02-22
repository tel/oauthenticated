# Oh! Authenticated!

  OAuth is a popular protocol allowing servers to offer resources
  owned by some user to a series of authorized clients securely. For
  instance, OAuth lets Twitter provide access to a user's private
  tweets to the Twitter client registered on their phone.

  `oauthenticated` is a Haskell library implementing OAuth protocols
  atop the popular `http-client` HTTP client library. The goal is to
  provide a general framework for signing
  'Network.HTTP.Client.Request's according to server parameters, a
  simple method for executing the common 3-arm OAuth token negotiation
  protocol, and a simplified API for accessing OAuth-protected
  resources.

  Currently `oauthenticated` only supports OAuth 1.0 and is in
  alpha. Further testing is needed before trustworthy use can be
  established. Further, OAuth 2.0 support is planned.

## Example

  See the `examples` directory for a script making a OAuth call to a URL
  with default parameters. Run `stack examples/oauth-authenticate.hs
  --help` for usage.
