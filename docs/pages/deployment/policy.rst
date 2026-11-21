.. _policy:

Access Token Policy
###################

Presentation Definition mapping
*******************************

Wallet functionality uses `Presentation Definitions <https://identity.foundation/presentation-exchange/>`_ to determine the required credentials for a given presentation request.
An OAuth2 authorization request uses scopes to determine the required permissions for a given request.
The mapping between scopes and presentation definitions is defined in a policy definition file.

How to design the policy for a use case is described on the wiki: `OAuth2 Scopes and Presentation Definition Mapping <https://wiki.nuts.nl/link/81>`_.

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

A policy definition file is a JSON object. Each key is an OAuth2 scope (``example_scope`` above); its value is the credential profile for that scope:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Required
     - Description
   * - ``organization``
     - one of these three
     - `Presentation Definition <https://identity.foundation/presentation-exchange/>`_ for the credentials of the organization's wallet.
       Required when the node, as OAuth2 client, uses its own policy file instead of the authorization server's ``presentation_definition`` endpoint
       (when the server doesn't advertise one, and always in the two-VP flow).
   * - ``service_provider``
     - one of these three
     - Presentation Definition for the credentials a service provider acting on behalf of a healthcare provider
       (the OAuth client in the RFC 7523 ``jwt-bearer`` flow) must present.
       It applies only to outbound RFC 7523 token requests initiated by the node.
       Experimental: requires ``auth.experimental.jwtbearerclient`` (default ``false``), see below.
   * - ``user``
     - one of these three
     - Presentation Definition for the credentials of the user's wallet.
       Experimental: only used in the OpenID4VP authorization code flow, which requires ``auth.authorizationendpoint.enabled`` (default ``false``).
   * - ``scope_policy``
     - no
     - How scopes requested next to this scope are handled:

       - ``profile-only`` (default): only this scope is allowed; a request with other scopes fails with ``invalid_scope``.
       - ``passthrough``: the other scopes are granted without evaluation.
       - ``dynamic``: all requested scopes are evaluated by an AuthZen policy decision point (``policy.authzen.endpoint``, required for this value).
         The request is denied if this scope is denied; other scopes are granted only when allowed.

Rules:

- A profile must define at least one of ``organization``, ``service_provider`` and ``user``.
- Each Presentation Definition is validated against the Presentation Exchange v2 JSON schema when the file is loaded.
- A scope may be defined only once, across all loaded files.
- An access token request may contain only one scope that has a credential profile.
- Constraint field ``id``\ s are checked when the file is loaded (see `Validation when loading`_). A violation stops the node from starting.

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

Fields with the same ``id`` (in several input descriptors, or in the ``organization`` and ``service_provider`` PDs) name one value and give one claim, see :ref:`policy-field-ids`.

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
      "type": "string",
      "pattern": "Admin level ([0-9])"
    }
  }

Only 1 capture group is supported in regular expressions. If multiple capture groups are defined, an error will be returned.

.. _policy-field-ids:

Field ids: one value per token request
**************************************

A constraint field ``id`` names a value. Within one token request, the same ``id`` means the same value everywhere: in every input descriptor of a Presentation Definition (PD) that declares it, and in the two-VP flow in both the ``organization`` and the ``service_provider`` PD.
This is a Nuts convention; Presentation Exchange itself gives a shared ``id`` no such meaning.

PD authors use it to relate credentials to each other.
For example, when the input descriptor for the care organization's credential and the input descriptor for a delegation both declare a field with ``id`` ``ura``,
the node only presents a delegation for the URA of the organization credential it presents, and a verifier rejects a presentation in which the two differ.
The ``id`` is also the claim name in the token introspection response, so fields sharing an ``id`` give one claim.
Use one ``id`` only for fields that really hold the same value; give unrelated values (e.g. the name of the organization and the name of the employee) different ``id``\ s.

Agreement
^^^^^^^^^

Two values agree when:

- both are strings, numbers or booleans and their text is equal. The string ``"1"`` agrees with the number ``1``, the string ``"true"`` with the boolean ``true``. Numbers are written in their shortest decimal form, without exponent;
- both are arrays, or both are objects, and they are equal as JSON.

A string, number or boolean never agrees with an array or object. The node applies the same rules when it selects credentials and when it checks a presentation it receives.

Pinned values
^^^^^^^^^^^^^

A value is *pinned* when it comes from outside the PD being built:

- the API caller's ``credential_selection`` (see `The credential_selection map`_);
- in the two-VP flow, the values carried over from the organization VP to the service-provider VP (see `Cross-VP binding via shared field.id`_).

A pinned value is strict: an input descriptor that declares the pinned ``id`` only accepts credentials whose field resolves to that value.
A field that does not resolve on a credential (an optional field), or that resolves to an array or object, never matches a pinned value.
A PD that does not declare a pinned ``id`` ignores it.

How credentials are selected
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When the node builds a presentation for a PD, it decides the credentials of all input descriptors together.
It keeps one list of selected values (field ``id`` → value), which starts with the pinned values:

1. The candidates of an input descriptor are the wallet's credentials that match its constraints and format, and that agree with the selected values on every ``id`` the input descriptor declares.
2. An input descriptor whose candidates all have the same values for its ``id``\ s is *decided*: it gets its first candidate, and the values of that credential are added to the selected values.
   This narrows down the candidates of every other input descriptor that declares those ``id``\ s. This step repeats until no input descriptor can be decided anymore.
   The order of the input descriptors in the PD does not matter for this step, except in one case:
   when two input descriptors are decided at the same moment but disagree on an ``id``, the first of them in PD order keeps its credential.
   The other is then narrowed down by that value, and gets no credential unless it has another candidate that agrees.
   This keeps alternatives working: e.g. two input descriptors of a submission requirement's ``pick`` rule that ask for the same claim from a JSON-LD credential
   and from a JWT credential, sharing an ``id``. The first one in PD order gets a credential, which is all the ``pick`` rule needs.
   Put the preferred alternative first.
3. When input descriptors are left whose candidates still differ:

   - if one of them declares a pinned ``id``, the request fails with *multiple matching credentials*, naming the input descriptor and the ``id``\ s on which its candidates differ.
     The caller pinned a value that leaves more than one choice; the caller can pin the other ``id``\ s as well.
   - otherwise, the first of them (in PD order) gets its first candidate, its values are added to the selected values, and step 2 continues.
     There is no backtracking: if that choice leaves another input descriptor without candidates, that input descriptor gets no credential. The caller avoids this by pinning the value.

4. An input descriptor without candidates gets no credential. Unless the PD's submission requirements allow that, the request fails with *missing credentials*.
   When the input descriptor had matching credentials that were all filtered out by a selected value, the error names the input descriptor and the ``id``.

What this means in practice:

- Credentials that agree on every ``id`` an input descriptor declares are interchangeable: the first one is used, also when the input descriptor declares a pinned ``id``.
  A request without pinned values never fails with *multiple matching credentials*.
- An input descriptor that shares no ``id`` with other input descriptors, and declares no pinned ``id``, gets its first matching credential.
- Related credentials follow what they relate to: when the organization is pinned (or the wallet holds only one organization credential),
  a delegation whose input descriptor shares the organization's ``id`` is the delegation of that organization, without pinning it as well.
- The node does not search for a combination that works. When the first choice is the wrong one (e.g. the first organization credential in the wallet has no delegation, the second has), pin the value.

Example: the wallet holds, in this order, the organization credentials ``P1`` (``ura`` 1) and ``P2`` (``ura`` 2), and the delegations ``D1`` (``ura`` 1) and ``D2`` (``ura`` 2).
The PD has an input descriptor for the organization credential and one for the delegation, both declaring ``ura``.

- With ``credential_selection`` ``{"ura": "2"}``, both input descriptors have one candidate left (``P2`` and ``D2``), so both are decided.
- Without ``credential_selection``, both input descriptors have two candidates that differ. The first input descriptor takes ``P1``, which adds ``ura`` 1; that leaves ``D1`` for the delegation.
  Before, each input descriptor took its first match on its own, which could combine an organization credential with the delegation of another organization.

Errors
^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 40 20

   * - Situation
     - Error
     - HTTP status (``request-service-access-token``)
   * - A ``credential_selection`` key that no PD of the request declares.
     - ``invalid_request``, naming every unknown key. Checked before any presentation is built.
     - 400
   * - An input descriptor without candidates, e.g. because no credential has the pinned value, or because its matches disagree with the credentials selected for other input descriptors.
     - *missing credentials* (``pe.ErrNoCredentials``), naming the input descriptor and, when a selected value filtered out its matches, the ``id``.
     - 412
   * - An input descriptor that declares a pinned ``id`` and whose candidates still differ on another ``id``.
     - *multiple matching credentials* (``pe.ErrMultipleCredentials``), naming the input descriptor and the ``id``\ s.
     - 500 (not mapped to a specific status)

Optional fields
^^^^^^^^^^^^^^^

A field marked ``optional`` that does not resolve on a credential gives no value: it adds nothing to the selected values and agrees with any value, both when selecting and when receiving.
Pinned values are the exception: an input descriptor that declares a pinned ``id`` only accepts credentials on which the field resolves to that value.

For PDs loaded from policy files and discovery service definitions, an ``id`` used in more than one input descriptor may not be on an optional field (see `Validation when loading`_),
so this only matters for an optional field whose ``id`` is used in one input descriptor, and for PDs fetched from a remote authorization server.

Receiving presentations
^^^^^^^^^^^^^^^^^^^^^^^

A node that receives a presentation rejects it when fields sharing an ``id`` resolve to values that do not agree (optional fields that do not resolve are ignored):

- the token endpoint (RFC 021 ``vp_token-bearer``) and the OpenID4VP response endpoint answer ``invalid_request``, naming the ``id`` and the input descriptors;
- a Discovery Server rejects the registration, and a Discovery Client does not return such a presentation in search results.

This includes presentations built by nodes running an older version, which selected a credential for each input descriptor on its own.

The node checks the mapping the presentation submission states: each input descriptor may only use the credential the submission maps to it,
and that credential must match the input descriptor, agree on shared ``id``\ s and satisfy the submission requirements.
Before, the node derived the mapping again by taking the first match for every input descriptor, and rejected the presentation when that differed from the submission.
So a presentation in which one credential matches several input descriptors is now validated as submitted.
The receiving side of the two-VP (``jwt-bearer``) flow is not implemented yet.

When values agree as text but differ in type (``"1"`` and ``1``), the introspection claim gets the value of the first input descriptor in PD order.

.. _policy-field-id-validation:

Validation when loading
^^^^^^^^^^^^^^^^^^^^^^^

When the node loads policy files and discovery service definitions, it checks the field ``id``\ s of their PDs:

- an ``id`` is unique within one input descriptor;
- for an ``id`` used in more than one input descriptor, filters that declare a ``type`` declare the same ``type``, and filters that declare a ``const`` declare the same ``const``
  (otherwise no credentials could ever agree). Filters without ``type`` or ``const`` are not compared;
- an ``id`` used in more than one input descriptor may not be on an ``optional`` field. An optional field whose ``id`` is used in only one input descriptor is allowed.

"More than one input descriptor" spans the ``organization`` and ``service_provider`` PDs of a credential profile together, since values carry over between them.
The ``user`` PD is checked on its own, as is the PD of each discovery service definition.

**A violation stops the node from starting.** The error names the file, the scope or service definition, the field ``id``, the input descriptors and the conflict.
PDs fetched from a remote authorization server are not checked.

Two-VP flow and cross-VP binding (experimental)
***********************************************

.. warning::
   The two-VP flow is **experimental**, under active development, and gated behind ``auth.experimental.jwtbearerclient = true`` (default ``false``).
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

Constraint fields with the same ``id`` across the two PDs bind the value presented in VP1 to the credential selection for VP2 (see `Field ids: one value per token request`_).
This lets policy authors express delegation requirements (e.g. *"VP2's delegation credential must be issued by the issuer of VP1's organization credential"*) without writing custom matcher code; the binding is realised through standard Presentation Exchange constructs.

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

1. The caller's ``credential_selection`` keys are checked against both PDs together; a key that neither declares fails the request with ``400 invalid_request`` before any VP is built.
2. VP1 is built from the HCP wallet against ``org_pd`` (see `How credentials are selected`_). The values of all fields with an ``id`` are resolved from the credentials in VP1: here the value at ``$.issuer`` of the credential that satisfied ``hcp_credential``, labelled ``delegating_hcp``.
3. Before VP2 is built, these values are added to the ``credential_selection`` map (see below), so they are pinned for VP2.
4. When VP2 is selected against ``sp_pd``, the wallet only considers ``ServiceProviderDelegationCredential`` candidates whose ``$.issuer`` equals the carried-over value, i.e. credentials delegated by the issuer of the HCP credential in VP1.

If the SP wallet has no delegation credential issued by that DID, the request returns ``pe.ErrNoCredentials`` (HTTP 412 Precondition Failed) and the EHR can show a clear "no delegation on file" error to the user.

Things to be aware of:

- VP1 is built first and is not reconsidered while VP2 is built. A key that only the ``service_provider`` PD declares does not influence which credentials VP1 presents.
  When the HCP wallet holds several credentials for ``hcp_credential`` and the first one has no counterpart in the SP wallet, the request fails with missing credentials; pin the value in ``credential_selection``.
- Values carried over from VP1 are pinned. An input descriptor of the ``service_provider`` PD that declares a carried-over ``id`` and still has candidates that differ on another ``id``
  (e.g. two delegations of the same HCP for different roles) fails the request with *multiple matching credentials*; pin the other ``id`` in ``credential_selection``.
- Values for ``id``\ s that only the ``organization`` PD declares are carried over as well; the ``service_provider`` PD ignores them.

The ``credential_selection`` map
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``credential_selection`` is a key-value map (string keys → string values) with which the caller pins values (see `Pinned values`_). Each key is a constraint field ``id``; values are the text the field should equal (strings, numbers and booleans are compared as text).
A PD that does not declare a key ignores it.
The EHR-supplied keys are checked against all PDs of the request together: in the single-VP flow the PD that is used (the authorization server's, when it advertises a ``presentation_definition`` endpoint), in the two-VP flow the ``organization`` and ``service_provider`` PDs.
A key that none of them declares results in ``400 invalid_request`` naming every unknown key; no presentation is built.

There are two sources of entries:

- **EHR-supplied** — the ``credential_selection`` field on the request body. EHRs typically use this for runtime context like a patient or encounter identifier (e.g. ``patient_id``), or to choose between credentials, such as the organization to act for.
- **Server-captured (two-VP only)** — entries populated automatically from the field values resolved from VP1, as described above. The capture is *additive*: any EHR-supplied key always wins. Strings, numbers and booleans are merged in as text; arrays and objects are skipped.

The same map is consulted by both single-VP and two-VP flows; the only difference is that the two-VP flow may add entries between VP1 and VP2.

Required configuration
^^^^^^^^^^^^^^^^^^^^^^

To enable the two-VP flow on a node:

1. Set ``auth.experimental.jwtbearerclient: true`` in the node config (off by default).
2. Provision the service-provider Nuts subject and its wallet via the existing wallet APIs. Its wallet must hold credentials matching the ``service_provider`` PD for any profile that should support the flow.
3. Add a ``service_provider`` PD block to each credential profile that should support the flow.
4. Have the EHR pass ``service_provider_subject_id`` on the access-token request body.

.. _policy-field-ids-upgrade:

Upgrading: field ids name one value
***********************************

Since field ``id``\ s name one value across a token request (`#4715 <https://github.com/nuts-foundation/nuts-node/issues/4715>`_), the node behaves differently in these ways:

- Policy files and discovery service definitions are checked when they are loaded (see `Validation when loading`_).
  A file that loaded before stops the node from starting when fields sharing an ``id`` declare different filter types or consts, when a shared ``id`` is on an optional field,
  or when an ``id`` is used twice within one input descriptor.
- Input descriptors that declare the same ``id`` get credentials that agree on its value, also across the two VPs of the two-VP flow.
  Before, each input descriptor took its first match on its own. A request can now present other credentials than before, or fail with missing credentials where it used to present credentials that did not agree.
- ``credential_selection`` keys that no PD of the request declares are rejected with ``400 invalid_request`` naming every unknown key, before any presentation is built.
  Before, the wallet rejected them with a generic error. In the two-VP flow, a key that only one of the two PDs declares used to fail the request and is now accepted.
- In the two-VP flow, values carried over from VP1 for an ``id`` that the ``service_provider`` PD does not declare no longer fail the request.
  Numbers and booleans are now carried over as text; before, only strings were.
- With ``credential_selection``, several matching credentials that agree on every ``id`` the input descriptor declares no longer fail with *multiple matching credentials*: the first is used.
  The error remains for credentials that differ on another declared ``id``, and it now names the input descriptor and the ``id``\ s.
  A *missing credentials* error names the ``id`` when a selected value filtered out the matching credentials.
- Presentations in which fields sharing an ``id`` have different values are rejected with ``invalid_request`` naming the ``id`` and the input descriptors,
  also when they come from nodes running an older version. Before, one of the values became the introspection claim, which one was not defined.
  A Discovery Server rejects such registrations, and a Discovery Client no longer returns them in search results.
- When two input descriptors that are decided at the same moment disagree on a shared ``id``, the first one in PD order keeps its credential and the other is narrowed down by its value (see `How credentials are selected`_).
- A received presentation is validated against the mapping its presentation submission states, instead of a mapping derived again by first match (see `Receiving presentations`_).
  Interoperability: a node on an older version still derives the mapping by first match. It can reject a presentation from this version in a corner case:
  one presented credential matches several input descriptors, and agreement on a shared ``id`` required another credential than the first match.

Known limitations:

- *Multiple matching credentials* is answered with HTTP 500 by ``request-service-access-token``, although the caller can resolve it by pinning another ``id`` (see `Errors`_).
- The node does not search for a combination of credentials that works: when the first choice has no counterpart, the request fails with missing credentials and the caller must pin the value.
  In the two-VP flow, VP1 is not reconsidered while VP2 is built.
- The receiving side of the two-VP (``jwt-bearer``) flow is not implemented yet.

Checklist for PD authors and operators, before upgrading:

1. List every constraint field ``id`` in your policy files (``organization``, ``service_provider`` and ``user`` PDs) and discovery service definitions.
2. Check that no ``id`` is used twice within one input descriptor.
3. For every ``id`` used in more than one input descriptor (counting the ``organization`` and ``service_provider`` PDs of a profile together),
   check that it is never on an ``optional`` field, and that the fields do not declare different filter ``type``\ s or ``const``\ s.
   Otherwise the node does not start. To find violations, start the new version with your configuration in a test environment: the error names the file, the scope or service definition and the ``id``.
4. For every shared ``id``, check that the fields really hold the same value (e.g. both paths hold the URA of the same organization).
   Rename ``id``\ s that are reused for unrelated values; otherwise only credentials whose values happen to be equal are selected, requests fail with missing credentials, and verifiers reject the presentations.
   Renaming an ``id`` changes the claim name in the token introspection response and the ``credential_selection`` key: update the resource servers and API callers that use it.
5. Check the ``credential_selection`` keys your API callers send: every key must be declared by a PD of the requested scope. In the single-VP flow this is the PD the authorization server serves, when it advertises one.
6. Where a wallet holds several credentials for an input descriptor (e.g. several organization credentials) and the caller does not pin a value, check that the first match is the intended one,
   or have the caller pin it: the node takes the first match and does not search for a combination that works.
7. Callers that pin a value and handled *multiple matching credentials*: this now only happens when the remaining credentials differ on another ``id`` of the input descriptor.
8. If you verify presentations (authorization server, Discovery Server) for PDs that share ``id``\ s, check with the parties requesting tokens or registering:
   presentations from nodes on an older version whose same-``id`` values differ are rejected.
