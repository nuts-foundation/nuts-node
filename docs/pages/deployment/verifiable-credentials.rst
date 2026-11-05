.. _verifiable-credentials-configuration:

Verifiable Credentials
######################

One of the most important features of the Nuts node is handling Verifiable Credentials.
This chapter describes the various configuration aspects of credentials in the Nuts node.

Custom Credential Configuration
*******************************

This section describes how to configure your Nuts node to handle custom credentials.

Introduction
^^^^^^^^^^^^

The Nuts node by default is configured to handle a set of Nuts credentials, such as `NutsOrganizationCredential` and `NutsEmployeeCredential`. These credentials are accepted and indexed automatically. If you want to use custom credentials for your use-case, you have to tell your Nuts node how they are structured.
A Verifiable Credential is structured as a JSON-LD document. Adding extra fields to a JSON-LD document requires adding an extra `@context`-definition which describes these fields.

To configure your Nuts node to recognise these extra fields and custom types, you have to overwrite the JSON-LD configuration. This can be done using the `jsonld.contexts` config. More information about configuration options and its default values can be found at the :ref:`config documentation <nuts-node-config>`.

The node can fetch a context from a http endpoint, but only if this location is explicitly listed as safe. For this you use the `jsonld.contexts.remoteallowlist`.
Or it can fetch the context definition from disk, using a mapping from url to path relative to current directory, or just using absolute paths. For this use the `jsonld.contexts.localmapping`

.. note::

    When configuring a list or map value, all values are replaced by your custom values. So if you want to just add an extra context and also use the Nuts context, make sure to add the default values to your config as well!

The default contexts can be accessed using the embedded file system `assets/contexts`. The contents of this directory can be found on Github: The default loaded contexts can be downloaded from the `Github repo <https://github.com/nuts-foundation/nuts-node/tree/master/vcr/assets/assets/contexts>`_.

The node uses JSON-LD contexts to normalize a credential when it creates or verifies a JSON-LD proof (``ldp_vc``, ``ldp_vp``), and to search credentials (``POST /internal/vcr/v2/search``).
So the node must know every context a credential uses; otherwise it can't verify or search it.
Credentials in JWT format (``jwt_vc``) are verified without the contexts.
Context URLs are identifiers: they don't have to resolve, as long as the node has a local mapping for them.

Built-in contexts (mapped to local files by default, see ``jsonld.contexts.localmapping``):

- ``https://www.w3.org/2018/credentials/v1``: W3C Verifiable Credentials
- ``https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json``: ``JsonWebSignature2020`` proofs
- ``https://w3id.org/vc/status-list/2021/v1``: StatusList2021 revocation
- ``https://schema.org``
- ``https://nuts.nl/credentials/v1``: Nuts credentials such as ``NutsOrganizationCredential`` and ``NutsAuthorizationCredential``
- ``https://nuts.nl/credentials/2024``: ``NutsUraCredential``

Background on JSON-LD in Nuts is on the `wiki <https://wiki.nuts.nl/link/196>`_.

Example configuration
^^^^^^^^^^^^^^^^^^^^^

Example configuration with an allowed remote context and another locally mapped context:

.. code-block:: yaml

    jsonld:
      contexts:
        remoteallowlist:
          - https://schema.org
          - https://www.w3.org/2018/credentials/v1
          - https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json
          - https://other-usecase-website.nl/use-case-context.ldjson
        localmapping:
          - https://nuts.nl/credentials/v1: "/abs/path/to/contexts/nuts.ldjson"
          - https://yourdomain.nl/custom-context.ldjson: "/abs/path/to/contexts/custom-context.ldjson"
          - https://default-context/v1.ldjson: "assets/contexts/lds-jws2020-v1.ldjson"
          - https://relative-path-usage/v42/ldjson: "./data/vcr/contexts/v42.ldjson"


Fetching & Caching
^^^^^^^^^^^^^^^^^^

During startup of the node, remote contexts are fetched and cached. If the contents of a remote context changes, the node must be restarted in order for these changes to have effect. Only remote context listed in the `remoteallowlist` are fetched.
Local mappings can be used to pin a version of a context, so no unseen changes can be made. Working with local mappings is also useful for developing purposes when the remote context is older or non-existent. When you work with local mappings, make sure all nodes involved in the use-case have the same custom context configured.

Searching and indexing
^^^^^^^^^^^^^^^^^^^^^^

Searching for custom credentials works just as Nuts provided credentials as described on the `wiki <https://wiki.nuts.nl/books/implementing-a-nuts-spec-v1-use-case/page/register-find-and-authorize-care-organizations>`_. Note however that the extra fields in the `credentialSubject` added by the custom credential are not indexed by the credential store. Searching for these fields is notably slower (depending on the query and amount of custom credentials). If this becomes a problem, inform the Nuts development team so an appropriate solution can be found.

Resources
^^^^^^^^^

- Introduction into JSON-LD: https://json-ld.org/
- The default loaded context definitions: https://github.com/nuts-foundation/nuts-node/tree/master/vcr/assets/assets/contexts
- Nuts node configuration options including the current default values: :ref:`config documentation <nuts-node-config>`
