##### Breaking Changes
* Split server and client specific auth code into two packages:
    * `com.zepben.auth.server`
    * `com.zepben.auth.client`

##### New Features
* Added client-side class that fetches authentication tokens, `ZepbenTokenFetcher`

##### Enhancements
* None.

##### Fixes
* Add 60 second leeway to JWT authentication

##### Notes
* None.