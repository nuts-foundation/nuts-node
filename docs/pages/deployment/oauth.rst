.. _oauth-profile:

OAuth2 Profile
##############

This page describes the OAuth2 related RFCs and where they are implemented.
The Nuts node implements (parts of) the following RFCs:

- `RFC 6749 <https://tools.ietf.org/html/rfc6749>`_ - The OAuth 2.0 Authorization Framework
- `RFC 7636 <https://tools.ietf.org/html/rfc7636>`_ - Proof Key for Code Exchange by OAuth Public Clients
- `RFC 7662 <https://tools.ietf.org/html/rfc7662>`_ - OAuth 2.0 Token Introspection
- `RFC 8414 <https://tools.ietf.org/html/rfc8414>`_ - OAuth 2.0 Authorization Server Metadata
- `RFC 9101 <https://tools.ietf.org/html/rfc9101>`_ - The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)
- `RFC 9449 <https://tools.ietf.org/html/rfc9449>`_ - OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- `Nuts RFC021 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc021-vp_token-grant-type>`_ - RFC021 VP Token Grant Type
- `OpenID4VP <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>`_ - OpenID for Verifiable Presentations - draft 20
- `Presentation Exchange <https://identity.foundation/presentation-exchange/>`_ - Presentation Exchange


There are two different flows implemented in the Nuts node to get an access token: Authorization Code Flow using OpenID4VP and the VP Token Grant type.

Authorization Code Flow
***********************

For the authorization code flow, the Nuts node implements the following:

- JAR (JWT Secured Authorization Request) for both the initial authorization request as well as the OpenID4VP authorization request.
- PKCE (Proof Key for Code Exchange) for the authorization code flow. The call of the initial authorization request is linked to the token request.
- DPoP (Demonstrating Proof of Possession) for the token request. Each resources request will require a new DPoP Proof header.
  The resource server is also required to check this header in an additional step after the token introspection.
- OpenID4VP for providing the VP token to the authorization server.

Both JAR and PKCE are mandatory. DPoP is optional, usage is determined by the client.
The Nuts node will do this automatically as client and authorization server.

VP Token Grant Type
*******************

The VP Token Grant Type is a new grant type that allows a client to request an access token using a verifiable presentation token.
It is a custom grant type that bypasses user interaction and allows a client to request an access token directly from the Nuts node.

The Nuts node implements the following:

- RFC021 VP Token Grant Type for the token request.
- DPoP (Demonstrating Proof of Possession) for the token request. Each resources request will require a new DPoP Proof header.
  The resources server is also required to check this header in an additional step after the token introspection.

DPoP is optional, usage is determined by the client.

DPoP
****

When the client wants to use DPoP, it must enable it in the access token request from client to Nuts node.
If enabled the client will also need to call the Nuts node to create a new DPop Proof header for each request to the resources server.

A resources server must check the type of access token used to request data. If a DPoP token is used, the resource server must verify the DPoP Proof using the hash of the public key from the introspection result.
The Nuts node provides a convenience API to do this for you.
Some of the calls to the Nuts node are required because it handles key material for the DPoP Proof. The keys used for the DPoP headers are taken from the DID Document of a tenant.
More information can be found on the `API documentation <nuts-node-api>`_ page. The relevant API's are:
- ``POST /internal/auth/v2/{did}/dpop``
- ``POST /internal/auth/v2/dpop_validate``