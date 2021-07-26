.. _using-concepts:

Using Concepts & VCs
####################

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
So calling `/internal/vcr/v1/vc` with

.. code-block:: json

    {
        "issuer": "did:nuts:ByJvBu2Ex21tNdn5s8FBnqmRBTCGkqRHms5ci7gKM8rg",
        "type": ["NutsOrganizationCredential"],
        "credentialSubject": {
            "id": "did:nuts:9UKf9F9sRtiq4gR3bxfGQAeARtJeU8jvPqfWJcFP6ziN",
            "organization": {
                "name": "Because we care B.V.",
                "city": "IJbergen"
            }
        }
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

Searching VCs
*************

Searching for VCs uses `concepts <vc-concepts>`_. The search API `/internal/vcr/v1/{concept}` requires a `concept` as path param.
One of the default concepts below defines the `organization` concept.
The search API accepts a `SearchRequest` body with key/value parameters. See the `API page <nuts-node-api>`_ for details on the request body.
The `key` field must be filled with one of the *conceptValues* from a concept template.

A valid request body when searching for a NutsOrganizationCredential:

.. code-block:: json

    {
        "params": [
            {
                "key": "organization.name",
                "value": "Because we care B.V."
            },
            {
                "key": "subject",
                "value": "did:nuts:1"
            }
        ]
    }


The result for a search request:

.. code-block:: json

    [
        {
            "id": "did:nuts:1#2",
            "issuer": "did:nuts:1",
            "subject": "did:nuts:2",
            "type": "NutsOrganizationCredential",
            "organization": {
                "name": "Because we care B.V.",
                "city": "EIbergen"
            }
        }
    ]

The **id**, **issuer**, **subject** and **type** fields are common and will always be returned. The rest is determined by the concept template mapping.

.. _default-concepts:

Preconfigured concepts
**********************

This page lists all preconfigured Verifiable Credentials used within a node.
See `VC Concept mapping <vc-concepts>`_ for background information on concept mapping.

NutsOrganizationCredential
==========================

.. include:: ../../../vcr/assets/NutsOrganizationCredential.config.yaml
   :literal:

NutsAuthorizationCredential
==========================

.. include:: ../../../vcr/assets/NutsAuthorizationCredential.config.yaml
   :literal:
