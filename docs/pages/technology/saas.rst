.. _saas_considerations:

SaaS Considerations
###################

While the Nuts node itself is small and lightweight, there are operational aspects of running a Nuts node
which could make parties consider to outsource hosting:

- Backing up data (both on-disk and in databases) and testing backup restore procedures
- Keeping the node up-to-date (patching)
- Securely handling private key material to avoid theft or data loss
- Key rotation

Additional Services
^^^^^^^^^^^^^^^^^^^

Additional services could involve;

- a UI for DID and credential administration
- middleware to support implementation of Nuts use cases (Zorgtoepassingen, e.g. eOverdracht),
  involving more in-depth integration with e.g. customer's FHIR servers.

Multi-tenancy
^^^^^^^^^^^^^

The Nuts node itself is not multi-tenant, meaning someone with access to its API can read and use any credential present on it.
This is a problem if the hoster of the node (e.g. SaaS vendor) does not control the applications using the API (care organization or EHR vendor).

By running a Nuts node for each customer, Therefore, it's recommended to run a separate Nuts node for each customer.

Things to consider:

- Securing node API access: the Nuts node provides API security using tokens, which could be extended with additional security measures for administrative access.
- Database separation: the Nuts node allows logical separation inside a single Redis database, but it's not thoroughly tested for multi-tenancy.
- Each node needs its own TLS certificate, having a single shared certificate is a risk (in case it gets blocked).

Architecture
^^^^^^^^^^^^

An example SaaS architecture could look as follows:

- Reverse proxy routing to Nuts nodes
- A Nuts node per customer
- Single Redis per customer or multi-tenant Redis Enterprise
- Private keys in a shared Hashicorp Vault (each customer having its own user)
- UI for administrating API access, DIDs and credentials
- Use case-specific middleware, AAA-Proxy for authorizing data access requests, and/or an API for initiating use cases (e.g. patient transfer)