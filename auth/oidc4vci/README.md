# Prototype for OIDC4VCI

## Resources:
[Notes on the wiki](https://wiki.nuts.nl/books/credential-issuance-and-presentation/page/notes-on-exploring-credential-issuance)


## Scope
Offer a NutsAuthorizationCredential using the OIDC4VCI specification.

## Decisions

## Prerequisites

- The issuer resolved the wallet's offer endpoint by searching the Nuts registry and looking up Wallet VC Offer Endpoint service (?).

## Code flow vs Pre-authentication flow
We only support the pre-authenticated code flow for now.
Rationale: for issuing credentials server-to-server the more complicated authorization code flow is not needed,
since it protects against stealing the pre-authentication code (e.g. scanning a QR-code 'over the shoulder') or phishing the end-user.
These are not applicable in a server-to-server scenario.

## Request examples
Here we describe all the requests and responses for obtaining the NutsAuthorizationCredential.

The issuer is hosted at `https://issuer.example` and the wallet is hosted at `https://wallet.example`.

### 1 Credential Offer

`GET` request from the issuer to the wallet's Offer Endpoint. Specifies `credential_offer` JSON object as query parameter:

```json
{
  "credential_issuer": "https://issuer.example",
  "credentials": [
    {
      "credential_issuer": "https://issuer.example",
      "format": "ldp_vc",
      "credential_definition": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://nuts.nl/credentials/v1"
        ],
        "types": [
          "VerifiableCredential",
          "NutsAuthorizationCredential"
        ]
      }
    }
  ],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "<secret_code>"
    }
  }
}
```

Invokes as:

```http request
GET https://wallet.example/offer/credential_offer?credential_offer=<URL encoded offer>
```

Notes:
- Unclear specification for the credential_offer for JSON-LD:
    - _4.1.1. Credential Offer Parameters_ specifies REQUIRED `credentials` parameter to contain the credentials that are offered,
      each one containing `format` and format-specific fields.
    - _E.1.3.3. Credential Offer (JSON-LD)_ specifies these fields for JSON-LD, which specifies REQUIRED `credential_definition`,
      but it is unclear whether this is a top-level field of the credential offer, or a field of the `credentials` entry.
      It also specifies (again) a `credential_issuer` field. Chosen to put `credential_issuer` again inside the credential spec,
      since the intention is (probably) that the issuer from 4.1.1 is the OIDC4VCI issuer, while the issuer from E.1.1.3 is the JSON-LD VC issuer(?).

### 2 Response

The wallet response with `202 - Accepted` without a body.

Notes:
- The response is unspecified by the OIDC4VCI spec.
  Chosen to return `202 - Accepted` without a body since the request is accepted,
  but the Wallet has to decide whether to do something with it.

### 3 Get Metadata

Upon accepting the credential offer, the wallet fetches the Credential Issuer Metadata from the well-known metadata endpoint:

```http request
GET https://issuer.example/.well-known/openid-credential-issuer
```

Notes:
- How to deal with issuers (care organizations) not having a (sub)domain of their own hosted by their vendor?
  Could we add a subpath before the .well-known path, or is this not allowed per RFC? (Can issuer even have a path after host+port?)

### 4 Response

The issuer responds with the metadata (`application/json`):

```json
{
  "credential_issuer": "https://issuer.example",
  "credential_endpoint": "https://issuer.example/credential",
  "credentials_supported": [
    {
      "format": "ldp_vc",
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1"
      ],
      "types": [
        "VerifiableCredential",
        "NutsAuthorizationCredential"
      ],
      "cryptographic_binding_methods_supported": "did:nuts"
    }
  ]
}
```

Notes:
- What should the wallet do with the info in `credentials_supported`?
  It won't support anything else than Nuts's VCs for now anyway(?).

### 5 POST pre-authorized code

### 6 Access Token Response

### 7 Request NutsAuthorizationCredential

### 8 Response NutsAuthorizationCredential



