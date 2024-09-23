.. _domain:

Choosing a domain name
######################

When deploying a Nuts node, you need to choose a domain name for the node.

.. code-block:: yaml

    url: https://example.com

The domain name is used in the following ways:

- It provides some information about the owner of DIDs and is part of the client_id in OAuth flows.
  Other parties can use the domain name to identify your node.
- It's part of the DIDs the node creates for you when you create a new subject.
  For example: DID web URLs are constructed as ``did:web:<domain>:iam:<uuid>``.
- It's listed in OAuth metadata.
  For example: the default identity URL is ``https://<domain>/oauth2/<subject>``.
  This URL is then used to lookup .well-known endpoints.
- It's part of the URL for the StatusList2021 revocation mechanism.

There are no strict requirements for the domain name, but please consider the following:

- You must own the domain name.
- The domain name should be stable.
  It should not change.
- It should use a TLD that allows for retention of the domain name.
  For example, a .com domain name can be blocked for a period of time after it's no longer registered.
  This will prevent the next owner from using it.
- The domain name should be human readable.
  Sub-domains from cloud providers are not recommended since they don't provide information about the owner.
- There should be a security.txt and robots.txt file at the root of the domain.
  This is a best practice for security and privacy.

Changing the domain name
************************

Changing the domain name of a Nuts node is basically the same as setting up a new node on a new domain.
All DIDs, VerifiableCredentials, Revocations, and other data is no longer usable.
You will not be able to revoke credentials. This means that all credentials issued by the old domain can no longer be trusted.
Actions should be taken to remove any trust that might have been established in your old identity.

As an issuer, you'll have to run the new domain side-by-side with the old domain for some time.

.. note::

    How long you should run the old domain side-by-side with the new domain depends on the use case and the validity of the credentials.
    As a rule of thumb, credentials should be renewed once a year, so you should run the old domain side-by-side with the new domain for at least a year.

As a holder, you'll have to generate DIDs for all your tenants and have issuers re-issue credentials.
This might involve a lot of manual work from your tenants.

As a verifier, nothing changes.

