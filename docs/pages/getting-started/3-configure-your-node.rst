.. _configure-node:

Setting up your node for a network
##################################

After you managed to start your node using either :ref:`docker <running-docker>` or :ref:`native <running-native>` it's time to connect to a network.

Overview
********

The steps to connect and register on a network look as follows:

- :ref:`configuring_step_bootstrap_node_tls_cert`
- :ref:`configuring_step_initial_synchronization`
- :ref:`configuring_step_registering_configuring_node_did`
- :ref:`configuring_step_verify`

These steps are explained in detail below.

Prerequisites
*************

The following is needed to connect a Nuts node to a network:

- A runnable node.
- A network you want to join.
- A TLS client- and server certificate which is accepted by the other nodes in the network (e.g. PKIoverheid).
- The public address of one or more remote nodes you'd like to use as bootstrap nodes.

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

The root CAs for the development and stable networks can be found in the ``https://github.com/nuts-foundation/nuts-development-network-ca`` repository.

For test and production `PKIoverheid Domein Private Services <https://cert.pkioverheid.nl/>`_ is used.
Make sure you load both the root certificate ("Stamcertificaat") and all intermediates (under "Domein Private Services").
Do not load any of the other certificates in your truststore.

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

Steps
*****

Follow the steps below to connect your node to a network and register its presence (node DID).

.. _configuring_step_bootstrap_node_tls_cert:

1. Configure bootstrap node(s) and TLS certificate
==================================================

A bootstrap node is just a normal Nuts node which is available for other nodes to connect to.
When you want to join a network, you must approach another network participant and ask for its public (gRPC) endpoint. Your node will have to connect to the bootstrap node's gRPC endpoint which is configured on port ``5555`` by default.
After connecting, you receive a copy of the current state of the network.
These transactions contain endpoints of other nodes. After a reboot, your node will try to connect to other nodes discovered in the network.

Consult the community on `Slack <https://nuts-foundation.slack.com/>`_ in the ``#development`` channel to find out which public bootstrap nodes are available to connect to your network of choice.

- configure the bootstrap nodes using ``network.bootstrapnodes``
- configure TLS using ``tls.certfile``, ``tls.certkeyfile`` and ``tls.truststorefile``

If you're using a YAML file to configure your node, the following snippet shows how to configure these properties:

.. code-block:: yaml

  tls:
    truststorefile: /path/to/truststore-development.pem
    certfile: /path/to/nuts.yourdomain.example-development.pem
    certkeyfile: /path/to/nuts.yourdomain.example-development.key
  network:
    bootstrapnodes:
      - nuts-development.other-service-provider.example:5555

See :ref:`configuration reference <nuts-node-config>` for a detailed explanation on how to exactly configure the Nuts node.

.. note::

    You can start the node without configuring the network, but it won't connect and thus exchange data with other nodes.
    You'll have a private network with one single node. Perfect for local development, but a bit lonely.

.. _configuring_step_initial_synchronization:

2. Initial synchronization
==========================

After configuring bootstrap node(s) and your node's TLS certificate, (re)start your node so it can synchronize with the network.
If you view the diagnostics page of the node, you should see it receiving transactions.
The time it takes for initial synchronization to complete highly depends on network state size and your node's rsources (CPU, memory and network bandwidth).
Your node is in sync when it stops receiving new transactions. You can then register your node's presence on the network.

.. _configuring_step_registering_configuring_node_did:

3. Registering and configuring Node DID
=======================================

Certain data (e.g. private credentials) can only be exchanged when a node's identity has been authenticated.
Your node identity is expressed by a DID managed by your node, also known as your *node DID*.

You first need to create a new DID document:

.. code-block:: text

    POST <internal-node-address>/internal/vdr/v1/did

Take note of the ``id`` field in the returned DID document; it will become your node DID.

You then need to make sure the DID document contains a ``NutsComm`` service,
which specifies the gRPC address other nodes will use to connect to your node.
The address must be in the form of ``grpc://<host>:<port>`` (e.g. ``grpc://nuts.nl:5555``).
The domain in the address (e.g. ``nuts.nl``) must exactly match (one of) the DNS SANs in your node's TLS certificate,
otherwise other nodes can't authenticate your node DID.

You can register the ``NutsComm`` service by calling the following DIDMan API:

.. code-block:: text

    POST <internal-node-address>/internal/didman/v1/did/<node-did>/endpoint
    {
        "type": "NutsComm",
        "endpoint": "grpc://nuts.nl:5555"
    }

Finally, configure it as ``network.nodedid`` (see :ref:`configuration reference <nuts-node-config>` and the configuration example below),
and restart your node for the changes to take effect.

.. note::

    - Multiple nodes may share the same DID, if they're governed by the same organization (e.g., clustered setups).
    - Node Discovery will ignore endpoints containing IP-addresses and reserved addresses as specified in `RFC2606 <https://datatracker.ietf.org/doc/html/rfc2606>`_.

.. _configuring_step_verify:

4. Verify Node Discovery and Authentication
===========================================

After restarting, check the diagnostics page:

.. code-block:: text

    GET <internal-node-address>/status/diagnostics

It will tell you:

- Which new nodes it discovered new nodes to which ones it is now connected.
- That your node DID is configured.

You're now set up to exchange data with other nodes.

Care Organizations
******************

The DID documents of your care organizations you (as a vendor) want to expose on the Nuts network need to be associated
with your node DID document (a.k.a. vendor DID) through the ``NutsComm`` endpoint.
Its recommended to register the actual ``NutsComm`` endpoint on your vendor DID document (as explained in the previous section),
and register a reference to this endpoint on the DID documents of your vendor's care organizations:

.. code-block:: text

    POST <internal-node-address>/internal/didman/v1/did/<care-organization-did>/endpoint
    {
        "type": "NutsComm",
        "endpoint": "<vendor-did>/serviceEndpoint?type=NutsComm"
    }
