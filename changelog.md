# Evolve SDK connection library
## [0.13.0] - UNRELEASED
### Breaking Changes
* None.

### New Features
* None.

### Enhancements
* None.

### Fixes
* JWTAuthenticator will now handle JwkExceptions and return 403 Unauthenticated responses.
* JWTAuthenticator will now pass through unhandled exceptions to the caller rather than wrapping them in 500 errors.
  Exceptions now need to be handled by the caller of `authenticate()`.

### Notes
* None.

## [0.12.0] - 2025-01-21
### Breaking Changes
* Update `fetchProviderDetails` to allow downstream users to set certificate verification. In addition, the default is changed for trust all certificates to using the default system store

### New Features
* None.

### Enhancements
* Replace use of the Auth0 `UrlJwkProvider` with our own `ConfigurableJwkProvider` so that we can customize the certificate verification behavior

### Fixes
* None

### Notes
* Update super POM to `0.37.0`, which update Vert.x to `4.5.11`

## [0.11.0] - 2024-10-18
### Breaking Changes
* Helper functions in ZepbenTokenFetcher now require specifying the AuthMethod.
* `JWTAuthoriser.authorise` no longer accepts a permissions claims field, instead it will attempt to retrieve claims from the "permissions" field if it exists in the token, or the "roles" field if the "permissions" field doesn't exist.
* `JWTAuthenticator` has a new signature to accept a list of trusted domains rather than a single domain, and a `JWTMultiIssuerVerifierBuilder` rather than a `UrlJwkProvider`.
* `Auth0AuthHandler` has a new signature and no longer accepts a `permissionsField` to pass onto `JWTAuthoriser.authorise`. (See above change to `JWTAuthoriser.authorise`)
* `AuthRoute.routeFactory` has a new signature. Now accepts a list of `TrustedIssuer`'s in place of a `urlJwkProvider` and `issuer`.

### New Features
* `JWTAuthenticator` now supports authenticating tokens from multiple different issues via the use of `JWTMultiIssuerVerifierBuilder`.
* `JWTMultiIssuerVerifierBuilder` will create a JWTVerifier based on the `iss` (issuer) of the token provided to `getVerifier()`. The returned JWTVerifier will
  also validate that the audience claim matches the `requiredAudience` supplied to the `JWTMultiIssuerVerifierBuilder`.
* `TrustedIssuer` now supports lazy fetching of `TrustedIssuer.providerDetails` by accepting a lambda that takes an issuer domain and returns a `ProviderDetails`. 

### Enhancements
* None.

### Fixes
* Now correctly handles issuers trailing slashes.
* Now correctly sending scope or audience to provider.

### Notes
* None.

## [0.10.0] - 2024-06-07
### Breaking Changes
* This is a breaking change as it changes the way the token fetcher works and has to be initialised. It means the clients using the `createTokenFetcher` helper functions or `ZepbenTokenFetcher`
  class directly would need to be updated to use the new interface.

### New Features
* A new `AuthProviderConfig` object can now hold the auth config exposed by EWB
* Simplified set of values exposed by EWB via `AuthConfigRoute`: issuer, audience, authMethod.
* A new helper functions to create AuthProviderConfig by fetching the data from EWB, and to fetch provider-related configuration (jwkUri, tokenEndpoint)
* `ZepbenTokenFetcher` is now using the new `AuthProviderConfig` object to fetch the auth config and the token.

### Enhancements
* None.

## [0.9.1] - 2024-06-07
### Fixes
* Revert AuthConfigRoute to use `issuerDomain` rather than `issuer`.
* Correctly refresh and store JWK keys on request

## [0.9.0] - 2024-05-14
### Breaking Changes
* None.

### New Features
* None.

### Enhancements
* None.

### Fixes
* Evolve-conn allowed the customization of the claim where permissions should be retrieved from. 
  This functionality only worked for gRPC requests. It has now been patched to work for HTTP requests as well
* AuthMethod Azure is renamed to EntraID

### Notes
* None.

## [0.8.0] - 2024-04-08
### Breaking Changes
* Use super pom version 0.34.x, which uses Vert.x version 4.4.6 (major version change 3 &rarr; 4).
* Removed unused module `com.zepben.auth.server.vertx`
* `AuthConfigRoute` now expects the key `issuer` instead of `issuerDomain` for the OAuth provider's hostname.

### New Features
* None.

### Enhancements
* None.

### Fixes
* After the move to vertx 4, we dropped using our own User module that ran Jwt token verifications. This fixes the 
issue by storing the token in the Vertx User object and verifying it separately.

### Notes
* None.

## [0.7.0] - 2023-11-10
##### Breaking Changes
* None.

##### New Features
* Support Azure Entra ID as an OAuth2 Auth provider
* Support Azure Identity token fetcher
* Support passing in your own authorisation callback to AuthInterceptor.

##### Enhancements
* `createTokenFetcher` now matches the authentication method (e.g. `OAUTH`) in the auth config JSON in a
  case-insensitive manner.

##### Fixes
* Refresh token is now used in token refresh requests.
* `createTokenFetcher` now defaults the token path to `\oauth\token` if it is unspecified in the auth config JSON.

##### Notes
* None.

## [0.5.0]
##### Breaking Changes
* There are 3 ways of specifying trusted TLS/SSL certificates when constructing a `ZepbenTokenFetcher`:
  * Directly specify the `HttpClient` via the `client` parameter
  * Specify whether to verify the certificate via the `verifyCertificate` parameter
  * Specify a CA file via the `caFilename` parameter
  
  This change prevents users of the library from trying to use more than one of these methods. A similar change was
  performed on the `createTokenFetcher` function; the following parameter groups are mutually exclusive:
  * `confClient` and `authClient`
  * `verifyCertificates`
  * `confCAFilename` and `authCAFilename`

##### New Features
* None.

##### Enhancements
* None.

##### Fixes
* Refresh token is now used in token refresh requests.

##### Notes
* None.
