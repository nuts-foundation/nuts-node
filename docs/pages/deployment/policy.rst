.. _policy:

Access Token Policy
###################

A policy definition file maps OAuth2 scopes to the `Presentation Definitions <https://identity.foundation/presentation-exchange/>`_
that say which credentials a client must present to get an access token for that scope.
Policy definition files are defined by the use case.

How to write a policy definition (file structure, claims in the token introspection response, the experimental service provider credentials)
is described on the wiki: `OAuth2 Scopes and Presentation Definition Mapping <https://wiki.nuts.nl/books/designing-a-nuts-use-case/page/oauth2-scopes-and-presentation-definition-mapping>`_.

Configuration
*************

To load policy definition files, configure the directory that contains them:

.. code-block:: yaml

    policy:
      directory: /path/to/directory

All JSON files in the directory will be loaded and used to define the mapping between scopes and presentation definitions.

Two-VP flow (experimental)
**************************

.. warning::
   The two-VP flow is **experimental**, under active development, and gated behind ``auth.experimental.jwtbearerclient = true`` (default ``false``).
   The ``service_provider`` PD block, the ``service_provider_subject_id`` API field, and the cross-VP binding mechanism are subject to change without notice while the underlying OAuth profile stabilises.

By default the node uses a single-VP token request (RFC 021 ``vp_token-bearer``). The two-VP RFC 7523 ``jwt-bearer`` flow runs only when **all** of the following hold:

1. The experimental flag ``auth.experimental.jwtbearerclient`` is ``true`` on the EHR-side node.
2. The EHR caller passes ``service_provider_subject_id`` in the body of ``POST /internal/auth/v2/{subjectID}/request-service-access-token``.
3. The remote authorization server advertises ``urn:ietf:params:oauth:grant-type:jwt-bearer`` in its metadata's ``grant_types_supported``.
4. The credential profile referenced by the request scope has a ``service_provider`` PD configured.

If conditions (2)-(4) are not all met when ``service_provider_subject_id`` is supplied, the request fails with a clear error rather than silently falling back to the single-VP flow.

To enable the two-VP flow on a node:

1. Set ``auth.experimental.jwtbearerclient: true`` in the node config (off by default).
2. Provision the service-provider Nuts subject and its wallet via the existing wallet APIs. Its wallet must hold credentials matching the ``service_provider`` PD for any profile that should support the flow.
3. Add a ``service_provider`` PD block to each credential profile that should support the flow.
4. Have the EHR pass ``service_provider_subject_id`` on the access-token request body.
