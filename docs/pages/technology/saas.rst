.. _saas_considerations:

SaaS Considerations
###################

While the Nuts node itself is small and lightweight, there are hard/expensive operational aspects of running a Nuts node:

- Backing up data (files on-disk and database records) and testing backup restore procedures
- Keeping the node up-to-date (patching)
- Securely handling private key material to avoid theft or data loss
- Key rotation

While some or all of these aspects apply to any software handling medical data,
parties could decide to outsource hosting of the Nuts node to a third party.

SaaS could be offered to those parties who do not want to deal with these aspects themselves.
These SaaS customers will probably be EHR system vendors themselves, or could be (large) care organizations who build and run their own software.
From SaaS perspective, this doesn't matter much but for simplicity we'll assume the SaaS customers are EHR system vendors,
who's customers are the actual care organizations.

Additional Services
^^^^^^^^^^^^^^^^^^^

Additional services could involve;

- a UI for DID and credential administration
- middleware to support implementation of Nuts use cases (Zorgtoepassingen, e.g. eOverdracht),
  involving more in-depth integration with e.g. customer's FHIR servers.

Multi-tenancy
^^^^^^^^^^^^^

The Nuts node itself is not multi-tenant, meaning someone with access to its API can read and use any credential present on it.
This is a problem if the hosting provider of the node (e.g. SaaS vendor) does not control the applications using the API (care organization or EHR vendor).

By running a Nuts node for each customer, API calls can only access resources (DIDs, keys) of that node.
Therefore, it's recommended to run a separate Nuts node for each SaaS customer.

Things to consider:

- Securing node API access: the Nuts node provides API security using tokens, which could be extended with additional security measures for administrative access.
- Database separation: the Nuts node allows logical separation inside a single Redis database, but it's not thoroughly tested for multi-tenancy.
- TLS certificates: currently every Nuts node has its own (PKIoverheid) certificate, meaning every vendor has their own.
  In a SaaS setup, having a single certificate for all nodes would be more convenient, but this poses risks:
   - A misbehaving node could be blocked based on its certificate, blocking all other nodes as well.
     But: there are rate limiters in place to prevent this from happening.
   - A certificate could be compromised (private key stolen) and gets revoked by the CA, blocking all SaaS nodes.
     But: if a single certificate is compromised, it's likely the entire SaaS platform is compromised as well.

Architecture
^^^^^^^^^^^^

An example SaaS architecture could look as follows:

- Reverse proxy routing to Nuts nodes
- A Nuts node per customer
- Single Redis per customer or multi-tenant Redis Enterprise
- Private keys in a shared Hashicorp Vault (each customer having its own user)
- UI for administrating API access, DIDs and credentials
- Use case-specific middleware, AAA-Proxy for authorizing data access requests, and/or an API for initiating use cases (e.g. patient transfer)