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

The Nuts node itself is not multi-tenant, meaning someone with access to its API can use any operation for all subjects.
This is a problem if the hosting provider of the node (e.g. SaaS vendor) does not control the applications using the API.
By running a Nuts node for each tenant, API calls can only access resources (DIDs, keys) of that node.
Therefore, for this scenario, it's recommended to run a separate Nuts node for each SaaS tenant.
