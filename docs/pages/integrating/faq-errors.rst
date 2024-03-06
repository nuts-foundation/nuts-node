.. _faq-errors:

Frequently Encountered Errors
#############################

This section lists commonly seen errors, what they mean and what to do about it.

Error: `connection closed before server preface received`
*********************************************************

When connecting to a remote node, the following error can occur:

    Couldn't connect to peer, reconnecting in XYZ seconds (peer=some.domain.nl:5555,err=unable to connect: context deadline exceeded: connection closed before server preface received)

This indicates the server is using TLS, but the local node is trying to connect without TLS.
Check the TLS settings.

Error: `JWT signing key not present on this node`
*************************************************

When inspecting an access token, the following error can occur:

    Error while inspecting access token (error: JWT signing key not present on this node)

This indicates the JWT token you send to the Nuts node can't be introspected by the Nuts node,
because it can't find the private key that was used to create the token. You probably:

#. Try to introspect a token that your node didn't create: only node that issued the token can introspect it. Or:
#. Your node's private key storage is corrupt and your node lost access to its private keys (less probable).

Error: `root transaction already exists`
****************************************

When you start your node, the following error can occur:

    Rolling back transaction application due to error (error: root transaction already exists)

This means your network state is incompatible with the node you're connecting to. This can be caused by:

#. an issue on the remote node's side or,
#. your node received/generated data from another network.

It's probably the latter problem. This typically happens when you create transactions (e.g. a DID document) before connecting to a network,
or when you (re)configure a bootstrap node which belongs to a different network.
The first situation (you created transactions before connecting to a network) is fixed by removing your node's data directory,
and following the :ref:`getting started documentation<configure-node>`.
The second situation is fixed by configuring the correct bootstrap node.

Error: `invalid nodeDID configuration`
*******************************************

When starting your node, the following error can occur:

    invalid nodeDID configuration: <error details>

Correctly configured nodes have a ``NutsComm`` service endpoint on the DID document of the configured ``network.nodeDID``,
and this address must be listed in the Subject Alternative Name section of the configured ``TLS certificate``.
A misconfiguration in any of these three items means that peers cannot authenticate the connection to your node,
and in strictmode this will prevent the node from starting. The ``<error details>`` will point you to the exact issue.
When in strict mode, remove the nodeDID from the configuration to view or change the ``NutsComm`` address.
In non-strictmode, the misconfiguration is logged as an error but it doesn't prevent the node from starting.