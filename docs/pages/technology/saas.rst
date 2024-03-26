.. _saas_considerations:

SaaS Considerations
###################

While the Nuts node itself is small and lightweight, there are hard/expensive operational aspects of running a Nuts node:

- Backing up data (files on-disk and database records) and testing backup restore procedures
- Keeping the node up-to-date (patching)
- Securely handling private key material to avoid theft or data loss
- Key rotation

While some or all of these aspects apply to any software handling sensitive data,
parties could decide to outsource hosting of the Nuts node to a third party.

Multi-tenancy
^^^^^^^^^^^^^

The Nuts node itself is not multi-tenant, meaning someone with access to its API can read and use any credential present on it.
This is a problem if the hosting provider of the node (e.g. SaaS vendor) does not control the applications using the API.

By running a Nuts node for each tenant, API calls can only access resources (DIDs, keys) of that node.
Therefore, for this scenario, it's recommended to run a separate Nuts node for each SaaS tenant.

Things to consider:

- Securing node API access: the Nuts node provides API security using tokens, which could be extended with additional security measures for administrative access.
- Database separation: the Nuts node allows logical separation inside a single Redis database, but it's not thoroughly tested for multi-tenancy.
- TLS certificates: currently every Nuts node has its own certificate, meaning every vendor has their own.
  In a SaaS setup, having a single certificate for all nodes would be more convenient, but this poses risks:
   - A misbehaving node could be blocked based on its certificate, blocking all other nodes as well.
     But: there are rate limiters in place to prevent this from happening.
   - A certificate could be compromised (private key stolen) and gets revoked by the CA, blocking all SaaS nodes.
     But: if a single certificate is compromised, it's likely the entire SaaS platform is compromised as well.

Architecture
^^^^^^^^^^^^

An example SaaS architecture could look as follows:

- Reverse proxy routing to Nuts nodes
- A Nuts node per tenant
- Single Redis per tenant or multi-tenant Redis Enterprise
- Private keys in a shared Hashicorp Vault (each tenant having its own user)
- UI for administrating API access, DIDs and credentials
- Use case-specific middleware, AAA-Proxy for authorizing data access requests, and/or an API for initiating use cases