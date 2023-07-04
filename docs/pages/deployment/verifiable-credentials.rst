.. _verifiable-credentials-configuration:

Verifiable Credentials
######################

One of the most important features of the Nuts node is handling Verifiable Credentials.
This chapter describes the various configuration aspects of credentials in the Nuts node.

Issuing and receiving over OpenID4VCI
*************************************

The Nuts node supports issuing and receiving credentials over OpenID Connect for `Verifiable Credential Issuance (OpenID4VCI)<https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>`_.
Discovery of issuer and wallets is done by looking up metadata on well-known endpoints.
To allow discovery of an issuer or wallet, its DID document must contain a service of type `node-http-services-baseurl`,
that specifies the HTTPS base URL of the `/n2n` interface of the node, excluding the latter.
E.g., when the node's `/n2n` interface is available on `https://example.com/n2n`, the endpoint to be registered is `https://example.com`.
As always, DID documents of care organization may reference the service in their vendor's DID document for easier administration.

Auto-registration
^^^^^^^^^^^^^^^^^

If the `node-http-services-baseurl` service is not registered for the DIDs on the local node, it will automatically try to register it.
For vendor DID documents (which have a `NutsComm` service that isn't a reference),
the node will inspect its TLS certificate's SANs and try to resolve its OpenID4VCI issuer metadata using a HTTP HEAD request.
E.g., give the SAN `nuts.example.com` and DID `did:nuts:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX`, it will attempt the following request:

```http
HEAD https://nuts.example.com/n2n/identity/did:nuts:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX/.well-known/openid-configuration
```

When the endpoint responds with `200 OK` and `Content-Type: application/json`,
the node will register the base URL (`https://nuts.example.com`) as `node-http-services-baseurl` service.

If the DID document contains a `NutsComm` service that refers to another DID document (typically for care organization's DID documents),
it will register a service reference the other DID document. But only if that DID document contains the `node-http-services-baseurl` service.

After the auto-registration succeeds the node's OpenID4VCI wallet is discoverable for other nodes,
and it can receive credentials from other nodes over OpenID4VCI.

Custom Credential Configuration
*******************************

This section describes how to configure your Nuts node to handle custom credentials.

Introduction
^^^^^^^^^^^^

The Nuts node by default is configured to handle a set of Nuts credentials, such as `NutsAuthorizationCredential` and `NutsOrganizationCredential`. These credentials are accepted and indexed automatically. If you want to use custom credentials for your use-case, you have to tell your Nuts node how they are structured.
A Verifiable Credential is structured as a JSON-LD document. Adding extra fields to a JSON-LD document requires adding an extra `@context`-definition which describes these fields.

To configure your Nuts node to recognise these extra fields and custom types, you have to overwrite the JSON-LD configuration. This can be done using the `jsonld.contexts` config. More information about configuration options and its default values can be found at the :ref:`config documentation <nuts-node-config>`.

The node can fetch a context from a http endpoint, but only if this location is explicitly listed as safe. For this you use the `jsonld.contexts.remoteallowlist`.
Or it can fetch the context definition from disk, using a mapping from url to path relative to current directory, or just using absolute paths. For this use the `jsonld.contexts.localmapping`

.. note::

    When configuring a list or map value, all values are replaced by your custom values. So if you want to just add an extra context and also use the Nuts context, make sure to add the default values to your config as well!

The default contexts can be accessed using the embedded file system `assets/contexts`. The contents of this directory can be found on Github: The default loaded contexts can be downloaded from the `Github repo <https://github.com/nuts-foundation/nuts-node/tree/master/vcr/assets/assets/contexts>`_.

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

Searching for custom credentials works just as Nuts provided credentials as described in :ref:`searching-vcs`. Note however that the extra fields in the `credentialSubject` added by the custom credential are not indexed by the credential store. Searching for these fields is notably slower (depending on the query and amount of custom credentials). If this becomes a problem, inform the Nuts development team so an appropriate solution can be found.

Resources
^^^^^^^^^

- Introduction into JSON-LD: https://json-ld.org/
- The default loaded context definitions: https://github.com/nuts-foundation/nuts-node/tree/master/vcr/assets/assets/contexts
- Nuts node configuration options including the current default values: :ref:`config documentation <nuts-node-config>`
