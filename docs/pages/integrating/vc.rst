.. _using-vcs:

Issuing and searching Verifiable Credentials
############################################

Issuing VCs
***********

As a node, you can issue credentials with each DID you control (whether they are trusted is a different story).
A credential is issued through the API or CLI.
The node will add sensible defaults for:

- @context
- id
- issuanceDate
- proof

You are required to provide the `credentialSubject`, the `issuer`, the `type` and an optional `expirationDate`.
So calling `/internal/vcr/v2/issuer/vc` with

.. code-block:: json

    {
        "issuer": "did:nuts:ByJvBu2Ex21tNdn5s8FBnqmRBTCGkqRHms5ci7gKM8rg",
        "type": "NutsOrganizationCredential",
        "credentialSubject": {
            "id": "did:nuts:9UKf9F9sRtiq4gR3bxfGQAeARtJeU8jvPqfWJcFP6ziN",
            "organization": {
                "name": "Because we care B.V.",
                "city": "IJbergen"
            }
        },
        "visibility": "public"
    }

Will be expanded by the node to:

.. code-block:: json

    {
      "context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1"
      ],
      "credentialSubject": {
        "id": "did:nuts:9UKf9F9sRtiq4gR3bxfGQAeARtJeU8jvPqfWJcFP6ziN",
        "organization": {
          "city": "IJbergen",
          "name": "Because we care B.V."
        }
      },
      "id": "did:nuts:ByJvBu2Ex21tNdn5s8FBnqmRBTCGkqRHms5ci7gKM8rg#a1d8ee3f-f404-44d5-bd07-71d3b144ce54",
      "issuanceDate": "2021-03-05T09:37:05.732811+01:00",
      "issuer": "did:nuts:ByJvBu2Ex21tNdn5s8FBnqmRBTCGkqRHms5ci7gKM8rg",
      "proof": {
        "created": "2021-03-05T09:37:05.732811+01:00",
        "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..s6lxJa7pOpqlhcWhJoKRMJIJiD4i+IUkfmhy+rUvNzZayVHAq+lZaFxBsv9rQCe0ewpZq/6z3hSUOURo6mnHhg==",
        "proofPurpose": "assertionMethod",
        "type": "JsonWebSignature2020",
        "verificationMethod": "did:nuts:ByJvBu2Ex21tNdn5s8FBnqmRBTCGkqRHms5ci7gKM8rg#gSEtbS2dOsS9PSrV13RwaZHz3Ps6OTI14GvLx8dPqgQ"
      },
      "type": [
        "NutsOrganizationCredential",
        "VerifiableCredential"
      ]
    }

The `visibility` property indicates the contents of the VC are published on the network, so it can be read by everyone.

Searching VCs
*************

You can search for VCs by providing a VC which should be used for matching in JSON-LD format.
Searching works by posting a Verifiable Credential to `/internal/vcr/v2/search` that contains fields to match.
The operation yields an array containing the matched verifiable credentials.

The example below searches for a `NutsOrganizationCredential` (note that the `query` field contains the credential):

.. code-block:: json

    {
        "query": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://nuts.nl/credentials/v1"
            ],
            "type": ["VerifiableCredential" ,"NutsOrganizationCredential"],
            "credentialSubject": {
                "id": "did:nuts:SKUYYi2g88ohjhiu49Q13ZWGXvp678sjNiM7UHUCMyw",
                "organization": {
                    "name": "Because we care B.V.",
                    "city": "IJbergen"
                }
            }
        }
    }

Note the fields `@context` and `type`, these are required for making it a valid VC in JSON-LD.
In the example above they also contain Nuts specific contexts and types (since we're searching for a Nuts VC).
The fields `@context` and `type` are not used as query parameters for searching, they are required to determine the right context.
The following query does not return all `NutsOrganizationCredential` but **all** credentials.

.. code-block:: json

    {
        "query": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://nuts.nl/credentials/v1"
            ],
            "type": ["VerifiableCredential" ,"NutsOrganizationCredential"],
        }
    }

To find certain credentials, you'll need to add fields that are required to exist in the desired credential.
The following query searches for credentials that have a organization name that starts with an empty string.
Any credential that does not have an organization name will be ignored.
By default, field selection is done by matching the given value as prefix.

.. code-block:: json

    {
        "query": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://nuts.nl/credentials/v1"
            ],
            "type": ["VerifiableCredential" ,"NutsOrganizationCredential"],
            "credentialSubject": {
                "organization": {
                    "name": ""
                }
            }
        }
    }

By default only VCs from trusted issuers are returned. You can specify the `searchOptions` field to include VCs from untrusted issuers.
