.. _external-secret-store:

Integrate with an external secret store
#######################################

.. note::

    The following functionality is experimental and subject to change. We encourage developers to test it out on a test network and provide feedback.

Motivation
**********

The Nuts-node represents entities in the network. These entities have cryptographic keys that are used to sign and encrypt data. The Nuts-node stores these keys in a secret store. The safety of the Nuts network depends on the security of these keys since the possession of the keys proofs ownership over the identity. For development purposes, the Nuts node contains a simple file based secret store. This is not recommended for production environments, and a safer alternative is advised. Since there are many different secret stores, the Nuts-node has been designed to be able to integrate with any secret store. This is done by using a proxy that acts as a bridge between the node and secret store. The Nuts-node communicates with this proxy using a standardised API. This way, the Nuts-node can be configured to use any secret store.

Implementing a proxy or building a custom secret store
******************************************************

A proxy or secret store should implement the Nuts Secret store API specification. This OpenAPI specification is available from the `Secret Store API repository <https://github.com/nuts-foundation/secret-store-api>`__.

This repository also provides integration tests which can be run against an implementation.

Consider developing your implementation under an open source license and publish it on a collaborative version control website such as `GitHub <https://github.com>`__ or `Gitlab <https://gitlab.com>`__ so that other parties can use it.

Reference implementation
************************

The Nuts community provides a supported reference implementation for the HashiCorp Vault secret store. This implementation is available on `GitHub <https://github.com/nuts-foundation/hashicorp-vault-proxy>`__.


Limitations
***********

The API has a few limitations:

- It does not yet support authentication. This means that the proxy should be secured in such a way that only the Nuts node can access the API.
