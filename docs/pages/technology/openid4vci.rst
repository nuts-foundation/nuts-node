.. _openid4vci:

OpenID 4 Verifiable Credential Issuance
#######################################

Nuts supports using `OpenID 4 Verifiable Credential Issuance (OpenID4VCI) <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>`_
to issue credentials directly from an issuer to a holder. By supporting this protocol we aim to improve compliance with industry standards and products
and remove credentials from the network DAG.

We currently only support the issuer initiated, pre-authorized code flow,
without PIN (since the issuance is server-to-server, without user involvement).

Further support leads from what Nuts supports, meaning:

- Only ``did:nuts`` DIDs are supported
- Only JSON-LD credentials are supported

We aim to support other flows and features in future:

- Authorization code and dynamic credential requests, when we want to support flows in which the holder requests issuance of a credential
- Client authentication, depending on evolving security requirements.

Enabling
********

By default, the feature is enabled.

But, for a DID to receive credentials over OpenID4VCI it needs to be discoverable,
meaning it needs a service of type ``node-http-services-baseurl``. The URL needs to point to the base URL of your node-to-node API,
e.g. ``https://nutsnode.example.com/`` (excluding ``/n2n``).
A background process ("golden hammer") tries to register this service for all of your node's DIDs automatically,
meaning in normal operation you don't need to do anything to start using OpenID4VCI.
