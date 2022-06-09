.. _configure-node:

Setting up your node for a network
##################################

After you managed to start your node using either :ref:`docker <running-docker>` or :ref:`native <running-native>` it's time to connect to a network.

Prerequisites
*************

The following is needed to connect a Nuts node to a network:

1. A runnable node.
2. The public address of one or more remote nodes you'd like to use as bootstrap nodes.
3. A TLS client- and server certificate which is accepted by the other nodes in the network (e.g. PKIoverheid).
4. A truststore containing the CA trust anchors for TLS certificates the network you're connecting to accepts (e.g. PKIoverheid).

To connect to the development network you can use the ``nuts-development-network-ca`` by cloning ``https://github.com/nuts-foundation/nuts-development-network-ca``.
That project contains scripts to generate certificates, and a truststore.

There are 2 networks for development/integration purposes:
- `development`: where new features are tested. Nodes will generally run the newest (not yet released) version of the Nuts node.
- `stable`: for integrating your software with Nuts and testing with other vendors. Nodes will generally run the latest released version (or at least a recent one).

Consult the community on `Slack <https://nuts-foundation.slack.com/>`_ to find out about how to connect to either network.

Configuring
***********

1. Configure the bootstrap nodes using ``network.bootstrapnodes``.
2. Configure TLS using ``network.certfile``, ``network.certkeyfile`` and ``network.truststorefile``.

See :ref:`configuration reference <nuts-node-config>` for a detailed explanation on how to exactly configure the Nuts node.


.. note::

    You can start the node without configuring the network, but it won't connect and thus exchange data with other nodes.

YAML Configuration File
=======================

If you're using a YAML file to configure your node, the following snippet shows an example for the network related configuration:

.. code-block:: yaml

  network:
    truststorefile: /path/to/truststore.pem
    certfile: /path/to/certificate-and-key.pem
    certkeyfile: /path/to/certificate-and-key.pem
    bootstrapnodes:
      - example.com:5555

Node TLS Certificate
====================

To connect to an existing Nuts network you need a TLS certificate which authenticates your node. For the development network
you can use the ``nuts-network-development-ca`` to directly issue a certificate for your node. The commands below clone
the required Git repository, generate a private key and issues a certificate, and combines them into a single file:

.. code-block:: shell

  git clone https://github.com/nuts-foundation/nuts-development-network-ca
  cd nuts-development-network-ca && ./issue-cert.sh localhost
  cat localhost.key localhost.pem > certificate-and-key.pem

.. note::

    If you want peers to be able to connect to your node, replace ``localhost`` with the correct hostname.

Note that the Git repository contains the Certificate Authority certificate (``ca.pem``) which will function as truststore.
Copy this file as ``truststore.pem`` into the working directory.

Node Identity
=============

Certain data (e.g. private credentials) can only be exchanged when a peer's DID has been authenticated.
To make sure other nodes can authenticate your node's DID you need to configure your node's identity,
and make sure the DID document contains a ``NutsComm`` service that matches the TLS certificate.

Your node identity is expressed by a DID that is managed by your node, also known as your *vendor DID*.
So make sure you have created a DID specific for your nodes and configure it as ``network.nodedid`` (see :ref:`configuration reference <nuts-node-config>`).

Then you make sure the associated DID Document contains a ``NutsComm`` endpoint,
where the domain part (e.g. ``nuts.nl``) matches (one of) the DNS SANs in your node's TLS certificate.
See "Node Discovery" below for more information on registering the ``NutsComm`` endpoint.

.. note::

    Multiple nodes may share the same DID, if they're governed by the same organization (e.g., clustered setups).

Node Discovery
==============

To allow your Nuts node to be discovered by other nodes, so they can connect to it,
you need to register a ``NutsComm`` endpoint on your vendor DID document.
The ``NutsComm`` endpoint contains a URL to your node's public gRPC service,
and must be in the form of ``grpc://<host>:<port>``.
E.g., if it were to run on ``nuts.nl:5555``, the value of the ``NutsComm`` endpoint should be ``grpc://nuts.nl:5555``

You can register the ``NutsComm`` endpoint by calling ``addEndpoint`` on the DIDMan API:

.. code-block:: text

    POST <internal-node-address>/internal/didman/v1/did/<vendor-did>/endpoint
    {
        "type": "NutsComm",
        "endpoint": "grpc://nuts.nl:5555"
    }

Care Organizations
******************

The DID documents of your care organizations you (as a vendor) want to expose on the Nuts network need to be associated
with your vendor's DID document through the ``NutsComm`` endpoint.
Its recommended to register the actual ``NutsComm`` endpoint on your vendor DID document (as explained in the previous section),
and register a reference to this endpoint on the DID documents of your vendor's care organizations:

.. code-block:: text

    POST <internal-node-address>/internal/didman/v1/did/<care-organization-did>/endpoint
    {
        "type": "NutsComm",
        "endpoint": "<vendor-did>/serviceEndpoint?type=NutsComm"
    }
