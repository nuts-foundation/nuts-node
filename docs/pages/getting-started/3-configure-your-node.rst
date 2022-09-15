.. _configure-node:

Setting up your node for a network
##################################

After you managed to start your node using either :ref:`docker <running-docker>` or :ref:`native <running-native>` it's time to connect to a network.

Prerequisites
*************

The following is needed to connect a Nuts node to a network:

1. A runnable node.
2. A network you want to join.
3. A TLS client- and server certificate which is accepted by the other nodes in the network (e.g. PKIoverheid).
4. The public address of one or more remote nodes you'd like to use as bootstrap nodes.
5. A node identity (node DID) to identify yourself in the network, so you can send/receive private transactions.

Networks
========

A network contains of a set of nodes who can all communicate with each other.
To make this possible, each of the nodes must meet the following requirements:

- Share a common set of trusted Certificate Authorities.
- Use a certificate issued by one of the CAs.
- The network transactions share the same root transaction.
- Use and accept network protocol versions from an agreed upon set.

There are 4 official Nuts networks:

- *development* where new features are tested. Nodes will generally run the newest (not yet released) version of the Nuts node.
- *stable* for integrating your software with Nuts and testing with other vendors. Nodes will generally run the latest released version (or at least a recent one).
- *test* for acceptance testing with other vendors and customers. Nodes will generally run the latest released version (or at least a recent one).
- *production* for production uses. Connecting to this network involves PKIoverheid certificates and outside the scope of this tutorial.

Node TLS Certificate
====================

Before you can join a network, your node needs a certificate from the correct Certificate Authority (CA). The ``development`` and ``stable`` networks are open for everyone to join. Contrary to the ``test`` and ``production`` networks (where we will be using a real Certificate Authority like PKIoverheid) the CA certificate and private key for these networks are available on github. This way you can generate your own certificate.

To generate the certificate for your own node you need the ``https://github.com/nuts-foundation/nuts-development-network-ca`` repository. It contains handy scripts and the needed key material. For more information how to use, consult the `README <https://github.com/nuts-foundation/nuts-development-network-ca/blob/master/README.md>`_

Your node only accepts connections from other nodes which use a certificate issued by one of the trusted CAs. Trusted CAs are using a truststore file. The truststore is a PEM file which contains one or more certificates from CAs which the network participants all decided on to trust.
To learn more about how a Nuts network uses certificates, see the specification `RFC008 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc008-certificate-structure>`_.


To generate certificates for the ``development`` network perform the following steps:

.. code-block:: shell

  git clone https://github.com/nuts-foundation/nuts-development-network-ca
  cd nuts-development-network-ca
  ./issue-cert.sh development nuts.yourdomain.example

This results in 3 files:

* ``nuts.yourdomain.example-development.key`` The private key for the node.
* ``nuts.yourdomain.example-development.pem`` The certificate for the node.
* ``truststore-development.pem`` The truststore for this (development) network.


Bootstrap nodes
===============

A bootstrap node is just a normal Nuts node which is available for other nodes to connect to.
When you want to join a network, you must approach another network participant and ask for its public (gRPC) endpoint. Your node will have to connect to the bootstrap node's gRPC endpoint which is configured on port ``5555`` by default.
After connecting, you receive a copy of the current state of the network.
These transactions contain endpoints of other nodes. After a reboot, your node will try to connect to other nodes discovered in the network.

Consult the community on `Slack <https://nuts-foundation.slack.com/>`_ in the ``#development`` channel to find out which public bootstrap nodes are available to connect to your network of choice.

Configuring
***********

1. Configure the bootstrap nodes using ``network.bootstrapnodes``.
2. Configure TLS using ``tls.certfile``, ``tls.certkeyfile`` and ``tls.truststorefile``.

See :ref:`configuration reference <nuts-node-config>` for a detailed explanation on how to exactly configure the Nuts node.


.. note::

    You can start the node without configuring the network, but it won't connect and thus exchange data with other nodes. You'll have a private network with one single node. Perfect for local development, but a bit lonely.

Node Identity
=============

Certain data (e.g. private credentials) can only be exchanged when a peer's DID has been authenticated.
To make sure other nodes can authenticate your node's DID you need to configure your node's identity,
and make sure the DID document contains a ``NutsComm`` service that matches the TLS certificate.

Your node identity is expressed by a DID that is managed by your node, also known as your *vendor DID*.
So make sure you have created a DID specific for your node and configure it as ``network.nodedid`` (see :ref:`configuration reference <nuts-node-config>`).

Then you make sure the associated DID Document contains a ``NutsComm`` endpoint,
where the domain part (e.g. ``nuts.nl``) matches (one of) the DNS SANs in your node's TLS certificate.
See "Node Discovery" below for more information on registering the ``NutsComm`` endpoint.

.. note::

    After registering ``nodedid`` you need to reboot your node in order have your connections authenticated, which is required to receive private transactions.

.. note::

    Multiple nodes may share the same DID, if they're governed by the same organization (e.g., clustered setups).


YAML Configuration File
=======================

If you're using a YAML file to configure your node, the following snippet shows an example for the network related configuration:

.. code-block:: yaml

  tls:
    truststorefile: /path/to/truststore-development.pem
    certfile: /path/to/nuts.yourdomain.example-development.pem
    certkeyfile: /path/to/nuts.yourdomain.example-development.key
  network:
    nodedid: did:nuts:123
    bootstrapnodes:
      - nuts-development.other-service-provider.example:5555

Node Discovery
==============

To allow your Nuts node to be discovered by other nodes (so they can connect to it) and be able to receive private transactions, you need to register a ``NutsComm`` endpoint on your vendor DID document.
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

.. note::

    The domain registered in the ``NutsComm`` endpoint must be listed as a DNS SAN in the node's TLS certificate.
    Node Discovery will ignore endpoints containing IP-addresses and reserved addresses as specified in `RFC2606 <https://datatracker.ietf.org/doc/html/rfc2606>`_.

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
