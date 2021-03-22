.. _running-native:

Getting Started with native binary
##################################

The Nuts executable this project provides can be used to both run a Nuts server (a.k.a. node) and administer a running
node remotely. This chapter explains how to run a server using the native binary.

Prerequisites
*************

The following is needed to run a Nuts node:

1. Nuts executable for your platform.
2. If connecting to an existing network: the public address of one or more remote nodes you'd like to use as bootstrap nodes.
3. A TLS client- and server certificate which is accepted by the other nodes in the network (e.g. PKIoverheid).
4. A truststore containing the CA trust anchors for TLS certificates the network you're connecting to accepts (e.g. PKIoverheid).
5. The public address of your Nuts node remote nodes can connect to.

To connect to the development network you can use the `nuts-development-network-ca` by cloning `https://github.com/nuts-foundation/nuts-development-network-ca`.

Configuring
***********

First you need to configure your Nuts node;

1. Configure the bootstrap nodes using `network.bootstrapnodes`.
2. Configure TLS using `network.certfile`, `network.certkeyfile` and `network.truststorefile`.
3. Configure the public address of your node using `network.publicaddr`.

See :ref:`configuration <nuts-node-config>` for a detailed explanation on how to exactly configure the Nuts node.


.. note::

    You _can_ start the node without configuring the network, but it won't connect and thus exchange data with other
    nodes.

Starting
********

Start the server using the `server` command:

    $ nuts server


