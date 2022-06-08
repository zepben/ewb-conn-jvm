#### Release History

| Version | Released |
| --- | --- |
| [0.5.0](#v050) | `TBD` |
| [0.4.0](#v040) | `4 March 2022` |
| [0.3.0](#v030) | `13 January 2021` |
| [0.1.0](#v010) | `08 October 2020` |

---

### v0.5.0

##### Breaking Changes
* None.

##### New Features
* Allow configuration of the maximum inbound message size for GrpcServer.
* Add GRPC server interceptor that compresses responses.

##### Enhancements
* None.

##### Fixes
* None.

##### Notes
* None.

---

### v0.4.0

##### Breaking Changes
* None.

##### New Features
* None.

##### Enhancements
* None.

##### Fixes
* None.

##### Notes
* None.

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
