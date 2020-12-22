#### Release History

| Version | Released |
| --- | --- |
|[0.3.0](#v030)| `TBD` |
| [0.1.0](#v010) | `08 October 2020` |

---

### v0.3.0

##### Breaking Changes
* Removed algorithm(alg) from the auth config response 
* Changed keys in auth config response to align with energy workbench server config:
    aud -> audience, dom -> issuer
* GrpcServer now takes a list of ServerInterceptors rather than just an AuthInterceptor.

##### New Features
* GrpcServer now supports multiple interceptors.
* Added an ExceptionInterceptor which can be used to intercept server side processing exceptions and propagate the 
  details to the client.

##### Enhancements
* Added auth type info in the auth config response

##### Fixes
* None.

##### Notes
* None.

---

### v0.1.0

Initial open source release of evolve-conn-jvm.