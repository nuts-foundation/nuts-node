.. _openid4vci:

Requesting Credentials over OpenID4VCI
#######################################

The Nuts node supports receiving Verifiable Credentials from an external issuer over `OpenID for Verifiable Credential Issuance (OpenID4VCI) <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>`_.
Your application triggers the credential request, the user authorizes it at the issuer, and the node receives and stores the credential.

Configuration
*************

To enable receiving credentials over OpenID4VCI, set ``auth.openid4vci.enabled`` to ``true``:

.. code-block:: yaml

    auth:
      openid4vci:
        enabled: true

When enabled, the node exposes:

- ``POST /internal/auth/v2/{subjectID}/request-credential`` — to initiate a wallet-initiated credential request.
- ``GET /oauth2/{subjectID}/callback`` — the redirect endpoint the issuer redirects back to after user authorization.

The ``url`` server option must be set to the node's publicly reachable base URL (e.g. ``https://example.com``),
since it is used to construct the callback URL sent to the issuer.

Flow
****

Your application initiates a request for a credential from a specific issuer.
The node handles the OAuth2 authorization code flow with PKCE, obtains an access token, and uses it
to retrieve and store the credential.

The flow proceeds as follows:

1. Your application calls ``POST /internal/auth/v2/{subjectID}/request-credential``.
2. The node returns a redirect URL pointing to the issuer's authorization endpoint.
3. Your application redirects the user-agent (browser) to that URL.
4. The user authorizes the credential issuance at the issuer.
5. The issuer redirects the user-agent back to the node's ``/oauth2/{subjectID}/callback`` endpoint.
6. The node exchanges the authorization code for an access token, then requests and stores the credential.
7. The node redirects the user-agent to the ``redirect_uri`` provided in step 1.

Step 1: Initiate the credential request
========================================

Call ``POST /internal/auth/v2/{subjectID}/request-credential`` with the following body:

.. code-block:: json

    {
      "wallet_did": "did:web:example.com:iam:9bc7d8e2",
      "issuer": "https://issuer.example.com/oauth2",
      "authorization_details": [
        {
          "type": "openid_credential",
          "credential_configuration_id": "HealthcareProviderRoleTypeCredential"
        }
      ],
      "redirect_uri": "https://my-xis.example.com/callback"
    }

Fields:

- ``wallet_did``: The DID that will be the subject of the issued credential. Must be a DID owned by the given ``subjectID``.
- ``issuer``: The OAuth2 Authorization Server URL of the credential issuer (as defined in RFC 8414), used to discover the issuer's endpoints (e.g. ``https://issuer.example.com/oauth2``).
- ``authorization_details``: Array of `authorization_details` objects (RFC 9396) describing the requested credentials. The ``credential_configuration_id`` value must match a credential configuration supported by the issuer; consult the issuer's credential issuer metadata (``/.well-known/openid-credential-issuer``) for supported values.
- ``redirect_uri``: The URL to which the user-agent is redirected after the node has received and stored the credential.

The node responds with a redirect URL:

.. code-block:: json

    {
      "redirect_uri": "https://issuer.example.com/oauth2/authorize?response_type=code&client_id=..."
    }

Step 2: Redirect the user-agent
================================

Redirect the user-agent (browser) to the returned ``redirect_uri``. The user will be prompted to authorize
the credential issuance at the issuer.

After authorization, the issuer redirects the user-agent back to the node's callback URL
(``{url}/oauth2/{subjectID}/callback``). The node exchanges the authorization code for an access token,
requests the credential, verifies it, and stores it in the wallet.

Finally, the node redirects the user-agent to the ``redirect_uri`` you provided in step 1.

Checking for errors
===================

If an error occurs during the callback phase (e.g. the issuer returns an error, or the credential cannot be verified),
the node redirects to the application's ``redirect_uri`` with an ``error`` query parameter:

.. code-block::

    https://my-xis.example.com/callback?error=access_denied&error_description=...

Your application should check for the ``error`` query parameter and handle it accordingly.

Using issued credentials
************************

Credentials received over OpenID4VCI are stored in the node's wallet. Once stored, they can be used like any
other credential held by the node — for example, to create Verifiable Presentations for authentication or
authorization flows.
