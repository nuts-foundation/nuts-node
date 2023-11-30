.. _discovery:

Discovery
#########

.. warning::
    This feature is under development and subject to change.

Discovery allows parties to publish information about themselves as a Verifiable Presentation,
so that other parties can discover them for further (data) exchange.

In this Discovery Service protocol there are clients and servers: clients register their Verifiable Presentations on a server,
which can be queried by other clients.
Where to find the server and what is allowed in the Verifiable Presentations is defined in a Discovery Service Definition.
These are JSON documents that are loaded by both client and server.

The Nuts node always acts as client for every loaded service definition, meaning it can register itself on the server and query it.
It only acts as server for a specific server if configured to do so.

Configuration
*************

Service definitions are JSON files loaded from the ``discovery.definitions.directory`` directory.
It loads all files wih the ``.json`` extension in this directory. It does not load subdirectories.
If the directory contains JSON files that are not (valid) service definitions, the node will fail to start.

To act as server for a specific discovery service definition,
the service ID from the definition needs to be specified in ``discovery.server.defition_ids``.
The IDs in this list must correspond to the ``id`` fields of the loaded service definition, otherwise the node will fail to start.