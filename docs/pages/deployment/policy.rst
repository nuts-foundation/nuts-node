.. _policy:

Access Token Policy
###################

Presentation Definition mapping
*******************************

Wallet functionality uses `Presentation Definitions <https://identity.foundation/presentation-exchange/>`_ to determine the required credentials for a given presentation request.
An OAuth2 authorization request uses scopes to determine the required permissions for a given request.
The mapping between scopes and presentation definitions is defined in a policy definition file.

Configuration
*************

The Nuts config supports the mapping between OAuth2 scopes and presentation definitions using a file-based configuration.
The file-based configuration is a simple way to define the mapping between scopes and presentation definitions.
It can be used for simple use cases where the mapping is static and does not change often.

To use file-based configuration, you need to define the path to a directory that contains policy definition files:

.. code-block:: yaml

    policy:
      directory: /path/to/directory

All JSON files in the directory will be loaded and used to define the mapping between scopes and presentation definitions.

Policy Structure
****************

JSON documents used for policies must have the following structure:

.. code-block:: json

    {
      "example_scope": {
        "organization": {
          "id": "example",
          "format": {
            "ldp_vc": {
              "proof_type": ["JsonWebSignature2020"]
            },
            "ldp_vp": {
              "proof_type": ["JsonWebSignature2020"]
            }
          },
          "input_descriptors": [
            {
              "id": "1",
              "constraints": {
                "fields": [
                  {
                    "path": ["$.type"],
                    "filter": {
                      "type": "string",
                      "const": "HumanCredential"
                    }
                  },
                  {
                    "id": "fullName",
                    "path": ["$.credentialSubject.fullName"],
                    "filter": {
                      "type": "string"
                    }
                  }
                ]
              }
            }
          ]
        }
      }
    }

Where ``example_scope`` is the scope that the presentation definition is associated with.
The ``presentation_definition`` object contains the presentation definition that should be used for the given scope.
The ``wallet_owner_type`` field is used to determine the audience type of the presentation definition, valid values are ``organization``, ``service_provider`` and ``user``.

The ``service_provider`` block describes the credentials that a service provider acting on behalf of a healthcare provider (the OAuth client in the RFC 7523 ``jwt-bearer`` flow) must present.
It applies only to outbound RFC 7523 token requests initiated by the node.
A profile may define any combination of ``organization``, ``service_provider`` and ``user`` blocks; at least one is required.

OAuth2 Token Introspection field mapping
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The input descriptor constraint fields that contain an ``id`` property (``input_descriptor.contraints.field.id``) are returned in the OAuth2 Token Introspection response.
The value of the Verifiable Credential that the matched field is included in the response as claims.
E.g., in the example above, a claim named ``fullName`` is added to the introspection response, containing the value of the ``credentialSubject.fullName`` property in the Verifiable Credential.
The following is an example OAuth2 Token Introspection response containing the ``fullName`` claim from the Presentation Definition
(some fields are omitted for brevity):

.. code-block:: json

  {
    "iss": "did:web:example.com",
    "active": true,
    "scope": "example_scope",
    "fullName": "John Doe"
  }

Writer of policies should take into consideration:
- fields that are intended to be used for logging or authorization decisions should have a distinct identifier.
- claims ideally map a registered claim name (e.g. `IANA JWT claims <https://www.iana.org/assignments/jwt/jwt.xhtml#claims>`_)
- overwriting properties already defined in the token introspection endpoint response is forbidden. These are: ``iss``, ``sub``, ``exp``, ``iat``, ``active``, ``client_id``, ``scope``.

Extracting substrings with regular expressions
==============================================
If you want introspection to return part of a string, you can use the ``pattern`` regular expression filter in the field definition with a capture group.
Token introspection will return the value of the capture group in the regular expression, instead of the whole field value.
For instance, if you want to extract the level from the string ``"Admin level 4"`` from the following credential:

.. code-block:: json

  {
    "credentialSubject": {
      "role": "Admin level 4"
    }
  }

You can define the following field in the input descriptor constraint, to have the level returned in the introspection response as ``admin_level``:

.. code-block:: json

  {
    "id": "admin_level",
    "path": ["$.credentialSubject.role"],
    "filter": {
      "type": "string"
      "pattern": "Admin level ([0-9])"
    }
  }

Only 1 capture group is supported in regular expressions. If multiple capture groups are defined, an error will be returned.

Presentation definition validation
**********************************

The node validates presentation definitions when loading policy files, and refuses to start on a definition
that would fail or misbehave on every request. All problems are reported at once. The checks are:

- **Duplicate ids.** An input descriptor id may be used once per definition, and a field id once per
  input descriptor. The same field id on fields of *different* descriptors is allowed and meaningful:
  the chosen credentials must agree on that field's value.
- **Same-id consistency.** Filters on fields that share an id must allow at least one common value.
  For example, a ``const`` on one descriptor that is not in another descriptor's ``enum`` for the same
  id can never be satisfied and fails validation. Two ``pattern`` filters without any ``const`` or
  ``enum`` are not checked (undecidable); such a conflict surfaces at request time instead.
- **Filters that can never match.** A ``const`` combined with a non-string ``type``, or an empty
  ``enum``, rejects every credential. A ``pattern`` that does not compile, or that has more than one
  capture group, errors on every evaluation.
- **Ignored constraints.** Keywords the matcher does not evaluate are rejected instead of silently
  weakening the filter: ``const`` or ``pattern`` next to ``enum`` (``enum`` takes precedence),
  ``pattern`` on a non-string ``type``, and unsupported JSON Schema keywords such as ``minimum``.
- **Submission requirements.** Every group referenced by an input descriptor must be covered by a
  submission requirement, rules must be ``all`` or ``pick``, exactly one of ``from``/``from_nested``
  must be set, and bounds must be possible (``min`` not above ``max``, no negative values).

A failing definition is reported with every conflict, for example::

  presentation definition 'example-care-pd' is invalid: active: const "true" can never match: it
  requires type "string", declared type is "boolean"; org_ura: conflicting filter types: string vs number

Guidance for policy authors:

- Issue claims whose values must be filtered or selected **as strings**. The matcher can require a
  value to be a number (``"type": "number"``), but cannot constrain a number's value: ``const``,
  ``enum`` and ``pattern`` compare as strings, and numeric JSON Schema keywords are not evaluated.
- Give every claim used for logging, authorization, or credential selection a distinct field ``id``;
  only declared field ids are returned by token introspection and usable in ``credential_selection``.
- When reusing a field ``id`` across input descriptors, make sure the filters agree: the id binds a
  single value across the chosen credentials.

Two-VP flow and cross-VP binding (experimental)
***********************************************

.. warning::
   The two-VP flow is **experimental** and gated behind ``auth.experimental.jwtbearerclient = true`` (default ``false``).
   The ``service_provider`` PD block, the ``service_provider_subject_id`` API field, and the cross-VP binding mechanism described below are subject to change without notice while the underlying OAuth profile stabilises.

When the two-VP flow runs
^^^^^^^^^^^^^^^^^^^^^^^^^

By default the node uses a single-VP token request (RFC 021 ``vp_token-bearer``). The two-VP RFC 7523 ``jwt-bearer`` flow runs only when **all** of the following hold:

1. The experimental flag ``auth.experimental.jwtbearerclient`` is ``true`` on the EHR-side node.
2. The EHR caller passes ``service_provider_subject_id`` in the body of ``POST /internal/auth/v2/{subjectID}/request-service-access-token``.
3. The remote authorization server advertises ``urn:ietf:params:oauth:grant-type:jwt-bearer`` in its metadata's ``grant_types_supported``.
4. The credential profile referenced by the request scope has a ``service_provider`` PD configured.

If conditions (2)-(4) are not all met when ``service_provider_subject_id`` is supplied, the request fails with a clear error rather than silently falling back to the single-VP flow.

How the two VPs are built
^^^^^^^^^^^^^^^^^^^^^^^^^

- **VP1 (organization)** — built from the wallet of the path-param ``subjectID`` (the healthcare provider, HCP), using the credential profile's ``organization`` PD. Sent as the ``assertion`` form parameter (RFC 7521 §4.1, the authorization grant).
- **VP2 (service_provider)** — built from the wallet of ``service_provider_subject_id`` (the OAuth client, the service provider acting on behalf of the HCP), using the credential profile's ``service_provider`` PD. Sent as the ``client_assertion`` form parameter (RFC 7521 §4.2, authenticating the client).

Each VP is signed with the holder DID's keys from the respective wallet.

Cross-VP binding via shared ``field.id``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Constraint fields with the same ``id`` across the two PDs implicitly bind a value captured from VP1 into the credential selection for VP2. This lets policy authors express delegation requirements (e.g. *"VP2's delegation credential must be issued by the DID that signed VP1"*) without writing custom matcher code; the binding is realised through standard Presentation Exchange constructs.

Example: a profile that requires VP2 to include a ``ServiceProviderDelegationCredential`` issued by the same DID as VP1's ``HealthcareProviderCredential``:

.. code-block:: json

    {
      "example_delegated_scope": {
        "organization": {
          "id": "org_pd",
          "input_descriptors": [{
            "id": "hcp_credential",
            "constraints": {
              "fields": [
                { "path": ["$.type"], "filter": { "type": "string", "const": "HealthcareProviderCredential" } },
                { "id": "delegating_hcp", "path": ["$.issuer"] }
              ]
            }
          }]
        },
        "service_provider": {
          "id": "sp_pd",
          "input_descriptors": [{
            "id": "delegation_credential",
            "constraints": {
              "fields": [
                { "path": ["$.type"], "filter": { "type": "string", "const": "ServiceProviderDelegationCredential" } },
                { "id": "delegating_hcp", "path": ["$.issuer"] }
              ]
            }
          }]
        }
      }
    }

How it works at request time:

1. VP1 is built. The matcher records the value at ``$.issuer`` of the credential that satisfied ``hcp_credential`` and labels it with the field id ``delegating_hcp``.
2. Before VP2 is built, that captured value is additively merged into the ``credential_selection`` map (see below).
3. When VP2 is selected against ``sp_pd``, the wallet only considers ``ServiceProviderDelegationCredential`` candidates whose ``$.issuer`` equals the captured value — i.e. credentials delegated by the exact HCP that signed VP1.

If the SP wallet has no delegation credential issued by VP1's HCP, the request returns ``pe.ErrNoCredentials`` (HTTP 412 Precondition Failed) and the EHR can show a clear "no delegation on file" error to the user.

The ``credential_selection`` map
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``credential_selection`` is a key-value map (string keys → string values) used to disambiguate between credentials when multiple satisfy a single input descriptor. Keys must match a constraint field ``id``; values are the literal string the field should equal for selection.

There are two sources of entries:

- **EHR-supplied** — the ``credential_selection`` field on the request body. EHRs typically use this for runtime context like a patient or encounter identifier (e.g. ``patient_id``).
- **Server-captured (two-VP only)** — entries populated automatically from VP1's matched constraint fields, as described above. The capture is *additive*: any EHR-supplied key always wins, and only string-typed captured values are merged in.

The same map is consulted by both single-VP and two-VP flows; the only difference is that the two-VP flow may add entries between VP1 and VP2.

Required configuration
^^^^^^^^^^^^^^^^^^^^^^

To enable the two-VP flow on a node:

1. Set ``auth.experimental.jwtbearerclient: true`` in the node config (off by default).
2. Provision the service-provider Nuts subject and its wallet via the existing wallet APIs. Its wallet must hold credentials matching the ``service_provider`` PD for any profile that should support the flow.
3. Add a ``service_provider`` PD block to each credential profile that should support the flow.
4. Have the EHR pass ``service_provider_subject_id`` on the access-token request body.