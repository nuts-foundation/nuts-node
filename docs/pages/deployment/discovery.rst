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

Discovery Server
================

To act as server for a specific discovery service definition,
the service ID from the definition needs to be specified in ``discovery.server.defition_ids``.
The IDs in this list must correspond to the ``id`` fields of the loaded service definition, otherwise the node will fail to start.

Discovery Client
================

Clients update their local copy of the Discovery Service at a set interval, this can be configured with ``discovery.client.refresh_interval``.

Usage
*****

Applications need to integrate with the Discovery Service to make their organization's discoverable for a use case,
and/or to find other organizations supporting a certain use case.

Registration
============

To make an organization discoverable through a Discovery Service, need to activate the organization's DID on that particular service.
This can be done by performing a HTTP POST to the ``/internal/discovery/v1/{serviceID}/{did}`` endpoint of the Nuts node,
where the service ID must match the ID of the service definition.
The Nuts node will try to create a Verifiable Presentation according to the Service Definition and register it on the Discovery Server.

Registration on the Discovery Service will only succeed if then the DID's wallet contains the required credentials.
If registration fails it will be retried after a set interval, which can be configured with ``discovery.client.registration_refresh_interval``.

The Nuts node will automatically refresh Verifiable Presentations that are about to expire.

Searching
=========

To find organization's through a Discovery Service, the application can search for Verifiable Presentations on a Discovery Service.
Querying is performed on the Verifiable Credentials within a Verifiable Presentation.
The caller specifies JSON path expressions as query parameters to match on.
For instance, to search match on the organization name property of a ``NutsOrganizationCredential``,
the caller can use the following HTTP request:

```http
GET /internal/discovery/v1/{serviceID}?credentialSubject.organization.name=Hospital%20First
```

Callers query in any string property within a Verifiable Credential, including nested properties. Arrays, numbers or booleans are not supported.
Wildcards can be used to search for partial matches, e.g. ``Hospital*`` or ``*First``.
If multiple query parameters are specified, all of them must match a single Verifiable Credential.