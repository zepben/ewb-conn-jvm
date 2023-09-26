# Evolve SDK connection library
## [0.7.0] - UNRELEASED
##### Breaking Changes
* None.

##### New Features
* Support Azure Entra ID as an OAuth2 Auth provider

##### Enhancements
* None.

##### Fixes
* Refresh token is now used in token refresh requests.

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
