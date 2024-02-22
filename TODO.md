# MitzXNuts POC merge to master TODOs


## Summary

OpenID4VCI API design in the Nuts node hasn't be made yet, but will probably not follow the design as implemented in the POC.
Authentication of the user must be considered if the user-agent (browser) is going to perform operations on the wallet in the Nuts node.

Useful bits, low-hanging-fruit to keep:
- `vdr/resolver/key.go` support for `@base` property in DID documents
- ES256K support (PR already exists for merge to master)

## General
- Why is session ID kept in the URLs everywhere?
- Remove `UnsecureSkipVerify` from TLS configuration
- Move well-known endpoints to the root (`/.well-known/...`)
- Thoughts for making POC-code more production ready
  - Code complexity (`for, for, if, for, if`)
  - println's
  - Ignored errors
  - Logging
- OpenID4VP and OpenID4VCI clients could be useful in future

## API endpoints

### /iam/{did}/start-oid4vci-issuance endpoint
Triggers start OpenID4VCI flow.

API design:
- Should be an internal endpoint, not exposed to the public. E.g. called by frontend for cloud wallet (Nuts node).
  - Something like /internal/iam/v1/{did}/request-credential
- Who calls this endpoint, the wallet front-end (thus the browser), or a back-end of the wallet front-end?
  - If it's a browser, it needs user authentication on the Nuts node wallet
  - If it's a back-end, the response shouldn't be a HTTP 302 with Location header, but a JSON response.

Implementation:
- PKCE code_challenge_method is not implemented properly, method must not be sent until access token request
- Returned errors should be user-friendly if browser calls the endpoint
- user_hint is now a signed JWT with session ID, is this functionally OK and secure? Do we want to use user_hint for this?

### /iam/oidc4vci/dcr/{sessionId}/.well-known/openid-configuration

- Missing properties should be added to existing metadata endpoint
- Why is metadata session specific?

### /iam/oidc4vci/dcr/{sessionId}/authorize
Triggers OpenID4VP flow within a OpenID4VCI flow (a.k.a. Dynamic Credential Request).

API design:
- Call for the browser? Same points as for `start-oid4vci-issuance` endpoint (probably internal endpoint, security considerations).
- Dynamic Credential Request is triggered by credential issuer (backend, state machine), not by the user (frontend, browser).

Implementation:
- Only 1 credential from Presentation Definition is supported
- VP format should be derived from what is supported by the involved parties

### /iam/oidc4vci/{sessionId}/callback
Who calls this?

API design:
- We're considering OAuth2 Client Registration, which involves pre-registered redirect URIs. This means they can't contain dynamic session IDs.

Implementation:
- The concept of credentials trust will be removed and is not applicable to did:web, OpenID4VCI and OpenID4VP as implemented in Nuts node.
  - Why was it needed in the POC?
- `authorization_servers` property in Credential Issuer Metadata was recently added and is optional, not sure if we want to support it?
  - Why was it needed in the POC?


### /internal/auth/v2/{did}/wallet

Remove, already exists as `/internal/vcr/v2/holder/{did}`

### DELETE /internal/auth/v2/{did}/wallet/{id)

To be implemented (https://github.com/nuts-foundation/nuts-node/issues/2820)

## Other code

- PKCE implementation we still need to implement, so could be useful. But we're not at that point yet.
  - Now stored separately from session, can be part of session struct? 
- `Wrapper.findCredentialWithDescriptors()`: use `PresentationDefinition.Match()` instead