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
- `StatusList2021 <https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/>`_ - Status List 2021
- `Presentation Exchange <https://identity.foundation/presentation-exchange/>`_ - Presentation Exchange


There are two different flows implemented in the Nuts node to get an access token: Authorization Code Flow using OpenID4VP and the VP Token Grant type.

Authorization Code Flow
***********************

For the authorization code flow, the Nuts node implements the following:

- JAR (JWT Secured Authorization Request) for both the initial authorization request as well as the OpenID4VP authorization request.
  All request use the ``request_uri`` parameter meaning that other request parameters cannot be inspected in the authorization request itself.
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

DPoP (`RFC 9449 <https://tools.ietf.org/html/rfc9449>`_) binds an access token to a key of the client.
With every request, the client sends a DPoP proof: a short-lived JWT, signed with that key, for the HTTP method and URL of that request.
A stolen access token can't be used without the key.

How the Nuts node uses DPoP:

- Access tokens are DPoP-bound by default. The client asks for a Bearer token by setting ``token_type`` to ``Bearer`` in the access token request
  (``POST /internal/auth/v2/{subjectID}/request-service-access-token`` and ``request-user-access-token``).
- The key is a key from the DID Document of the requesting subject, so it is held by the Nuts node, not by the client application.
  The access token response contains it as ``dpop_kid``, next to ``token_type: DPoP``.
- As authorization server, the Nuts node records the key's thumbprint with the access token.
  Token introspection returns it as ``cnf.jkt``. It is absent for Bearer tokens.

How to use it:

1. **Client:** for each request to the resource server, call ``POST /internal/auth/v2/dpop/{kid}`` with the ``dpop_kid`` (URL-encoded),
   the access token, and the HTTP method and URL of the request.
   Send the returned proof in the ``DPoP`` HTTP header and the access token as ``Authorization: DPoP <access token>``.
2. **Resource server:** introspect the access token. If the response has ``cnf.jkt``, require the ``DPoP`` scheme and a ``DPoP`` header,
   and validate the proof with ``POST /internal/auth/v2/dpop/validate`` (proof, method, URL, access token, and ``cnf.jkt`` as ``thumbprint``).
   This checks the signature, method, URL, thumbprint, access token hash (``ath``) and that the proof is used only once (``jti``).
   Other checks required by RFC 9449 remain the resource server's responsibility.

Request and response fields are in the `API documentation <nuts-node-api>`_.
Step-by-step guides for a use case are on the wiki:
`Make the FHIR call <https://wiki.nuts.nl/link/182>`_ and `Validate the access token <https://wiki.nuts.nl/link/110>`_.

StatusList2021
**************

The revocation status of presented Verifiable Credentials that contain a ``credentialStatus`` with type ``StatusList2021Entry`` will automatically be validated.
To issue a Verifiable Credential that can be revoked, see ``POST /internal/vcr/v2/issuer/vc`` in the `API documentation <nuts-node-api>`_.
Be aware that the Nuts-node hosts a ``StatusList2021Credential`` with the revocation status of all issued credentials.
This endpoint MUST be available for some time after the last VC on the list has been revoked, or until all VCs on the list have expired.