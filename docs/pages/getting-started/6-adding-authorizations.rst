.. _getting-started-authorizations:

Getting started with Authorizations
###################################

Authorization is one of the three core concepts of Nuts (the others being identification and addressing).
Authorization comes in the form of a `NutsAuthorizationCredential <https://nuts-foundation.gitbook.io/drafts/rfc/rfc014-authorization-credential>`_.
An authorization credential is a privately distributed credential that answers:

- which **custodian** controls the resources
- to which **patient** do the resources belong to
- which **actor** may access the resources
- what is the **scope** of the authorization
- on what **legal base** is the authorization provided
- which individual **resources** may be accessed

Authorization credentials are issued by the same party that will also control the access to the resources.

Bolt
****

A Bolt is a functional and technical specification that translates a care process to technical requirements.
An authorization is created for a particular Bolt. A Bolt specifies what the possible values of `purposeOfUse` can be.
Each value corresponds to an access policy defined by the Bolt.
Creating an authorization credential that is not according to a Bolt specification will have little effect or will even hinder interoperability.
Particular requirements for a Bolt are not validated by the node, the node will only do the validations as specified.

Registering a NutsAuthorizationCredential
*****************************************

Issuing an authorization credential is similar to issuing an organization credential. Both use the same API.
New credentials will automatically receive an `id`, `issuanceDate`, `context` and `proof`.
A DID requires a valid `assertionMethod key <https://nuts-foundation.gitbook.io/drafts/rfc/rfc011-verifiable-credential#3-1-1-jsonwebsignature2020>`_.

The credential can be issued with the following call:

.. code-block:: text

    POST <internal-node-address>/internal/vcr/v1/vc
    {
        "issuer": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv",
        "type": ["NutsAuthorizationCredential"],
        "credentialSubject": {
            "id": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv",
            "legalBase": {
                "consentType": "implied"
            },
            "resources": [
                {
                    "path": "/test",
                    "operations": ["read"],
                    "userContext": true
                }
            ],
            "purposeOfUse": "test-service",
            "subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
        }
    }

As you can see, there are quite some fields to fill out.
The following paragraphs will dig deeper into the different parts.

issuer
======
The `issuer` is the resource owner. It must be a DID of an organization for which you control the private key.
The DID typically comes from your own administration, see also :ref:`Getting Started on customer integration <connecting-crm>`_.

type
====
The `type` must equal `["NutsAuthorizationCredential"]`, no exceptions.

credentialSubject.id
====================
The `credentialSubject.id` is the receiver or *holder* of the credential.
It must be a DID of an organization. This DID is typically found via a search call.
The following call will search for an organization with the name *CareBears*.

.. code-block:: text

    POST <internal-node-address>/internal/vcr/v1/organization
    {
        "Params": [
            {
                "key": "organization.name",
                "value": "CareBears"
            }
        ]
    }

The :ref:`concept development page <using-concepts>`_ contains some more information on how to perform searches.
The result of the call above will be something like this:

.. code-block:: json

    [
        {
            "id": "did:nuts:3wEb8GJEuenjMexQXKfrdAr8CvA69SdbVh8qhUpDMcX2#dd4193e6-cc94-4276-88c3-8b272612c50f",
            "issuer": "did:nuts:3wEb8GJEuenjMexQXKfrdAr8CvA69SdbVh8qhUpDMcX2",
            "organization": {
                "city": "CareTown",
                "name": "CareBears"
            },
            "subject": "did:nuts:5vLpJpRP8KnQbTL4XC78VtfdNabwNGfDtTTWXDkAkXBm",
            "type": "NutsOrganizationCredential"
        }
    ]

The `subject` field is the DID that would be the receiver of the credential.


credentialSubject.purposeOfUse
==============================
The `credentialSubject.purposeOfUse` field will be filled with a fixed value.
A Bolt specification will describe what value to put here.

credentialSubject.subject
=========================
The `credentialSubject.subject` field identifies the patient.
Resources that are scoped to a patient will have an authorization record with a patient identifier.
It's possible for authorization records to not include this field.
A Bolt specification should describe when to use this field and when not.
The contents in this example is a **urn** with a Dutch citizens number.

credentialSubject.legalBase
===========================
This field describes the legal base from which the authorization credential originates.
A Bolt will what values are to be entered.

credentialSubject.resources
===========================
The resources array describes what resources may be accessed with the authorization credential.
Unless stated otherwise by the Bolt, these resources are in addition to any common resources listed by the access policy of the Bolt.
A resource has 3 members: `path`, `operations` and `userContext`.
See `the Nuts specification <https://nuts-foundation.gitbook.io/drafts/rfc/rfc014-authorization-credential#3-2-4-resources>`_ for more detail.

Searching for authorization credentials
***************************************

Authorization credentials can be used as a distributed index: *where can I find information for patient X?*.
When an access token is requested via the API, references to the relevant authorization credentials are required.

To find the relevant authorization credentials, the credential search API can be used.
To find all authorization credentials of a single patient:

.. code-block:: text

    POST <internal-node-address>/internal/vcr/v1/authorization?untrusted=true
    {
        "Params": [
            {
                "key": "credentialSubject.id",
                "value": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv"
            },
            {
                "key": "credentialSubject.subject",
                "value": "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
            }
        ]
    }

The call above includes a query for a particular *receiver* via the `credentialSubject.id` key.
This would typically be a DID from your own administration.
The second parameter defines the patient.
This example will return a list of authorization credentials where the `credentialSubject.purposeOfUse` field will indicate what kind of information can be retrieved.
The `untrusted` query parameter must be added because authorization credentials are not issued by a trusted third party but by organizations themselves.

It can also be the case that you need to find an authorization that covers a certain request.
If you want to call `/patient/2250f7ab-6517-4923-ac00-88ed26f85843` for a particular Bolt, you can use:

.. code-block:: text

    POST <internal-node-address>/internal/vcr/v1/organization?untrusted=true
    {
        "Params": [
            {
                "key": "credentialSubject.id",
                "value": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv"
            },
            {
                "key": "credentialSubject.purposeOfUse",
                "value": "test-service"
            },
            {
                "key": "credentialSubject.resources.#.path",
                "value": "/patient/2250f7ab-6517-4923-ac00-88ed26f85843"
            }
        ]
    }

This call will return all authorization credentials with a `purposeOfUse` equal to `test-service` and with which you are allowed to call the resource located at `/patient/2250f7ab-6517-4923-ac00-88ed26f85843`
Any value in an authorization credential can be used as a param in the search API.
The search `key` requires a valid JSON path expression.

Return values
=============

When searching for authorization credentials, the credentials are returned as a verifiable credential.
Most of the time, you'll only need the credential identifier, available in the root `id` field.

Example return value:

.. code-block:: json

    [
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://nuts.nl/credentials/v1"
            ],
            "credentialSubject": {
                "id": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv",
                "legalBase": {
                    "consentType": "implied"
                },
                "purposeOfUse": "test-service",
                "resources": [
                    {
                        "operations": [
                            "read"
                        ],
                        "path": "/patient/2250f7ab-6517-4923-ac00-88ed26f85843",
                        "userContext": true
                    }
                ],
                "subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
            },
            "id": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv#314542e8-c8cc-4502-a7df-a815ac47c06b",
            "issuanceDate": "2021-07-26T14:36:10.163463+02:00",
            "issuer": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv",
            "proof": {
                "created": "2021-07-26T14:36:10.163463+02:00",
                "jws": "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..k4cda7fMY05mnp4gsNJ3hNExjsSz3mqymyo4xJWkbb9-1URljVWIzPg6R62T-YETV7UXvz1X9QteuhbmoM1JLA",
                "proofPurpose": "assertionMethod",
                "type": "JsonWebSignature2020",
                "verificationMethod": "did:nuts:JCJEi3waNGNhkmwVvFB3wdUsmDYPnTcZxYiWThZqgWKv#_3uOS5FqcyGj-cn-Yynv5epH0UVqbt_2BWXPfy0oKnU"
            },
            "type": [
                "NutsAuthorizationCredential",
                "VerifiableCredential"
            ]
        }
    ]
