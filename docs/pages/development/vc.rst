.. _using-concepts:

Using Concepts & VCs
####################

Issuing VCs
***********

As a node, you can issue credentials with each DID you control (If they are trusted is a different story).
A credential is issued through the API or CLI. The format of the Verifiable Credential is required, not the concept format.
The node will add sensible defaults for:

- @context
- id
- issuanceDate
- proof

You are required to provide the `credentialSubject`, the `issuer`, the `type` and an optional `expirationDate`.
So calling `/internal/vcr/v1/vc` with

.. code-block:: json

    {
        "issuer": "did:nuts:123",
        "type": "ExampleCredential",
        "credentialSubject": {
            "id": "did:nuts:321",
            "company": {
                "name": "Because we care B.V.",
                "city": "IJbergen"
            }
        }
    }

Will be expanded by the node to:

.. code-block:: json

    {
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "id": "did:nuts:123#3732",
        "type": ["VerifiableCredential", "ExampleCredential"],
        "issuer": "did:nuts:123",
        "issuanceDate": "2021-03-01T12:00:00Z",
        "credentialSubject": {
            "id": "did:nuts:321",
            "company": {
                "name": "Because we care B.V.",
                "city": "IJbergen"
            }
        },
        "proof": { }
    }

.. _default-concepts:

Preconfigured concepts
**********************

This page lists all preconfigured Verifiable Credentials used within a node.
See `VC Concept mapping <vc-concepts>`_ for background information on concept mapping.

NutsOrganizationCredential
==========================

.. include:: ../../../vcr/assets/NutsOrganizationCredential.json
   :literal: