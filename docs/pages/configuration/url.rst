.. _nuts-node-url:

The node's URL
###############

The ``url`` option is the node's public facing URL:

.. code-block:: yaml

    url: https://example.com

It's used in the following ways:

- It provides some information about the owner of DIDs and is part of the client_id in OAuth flows.
  Other parties can use it to identify your node.
- It's part of the DIDs the node creates for you when you create a new subject.
  For example: DID web URLs are constructed as ``did:web:<domain>:iam:<uuid>``.
- It's listed in OAuth metadata.
  For example: the default identity URL is ``https://<domain>/oauth2/<subject>``.
  This URL is then used to lookup .well-known endpoints.
- It's part of the URL for the StatusList2021 revocation mechanism.

There are no strict requirements for it, but please consider the following:

- You must own the domain.
- The domain should be stable. It should not change.
- It should use a TLD that allows for retention of the domain name.
  For example, a .com domain name can be blocked for a period of time after it's no longer registered.
  This will prevent the next owner from using it.
- The domain should be human readable.
  Sub-domains from cloud providers are not recommended since they don't provide information about the owner.
- There should be a security.txt and robots.txt file at the root of the domain.
  This is a best practice for security and privacy.

Once chosen, changing it is a disruptive operation; see :ref:`changing-base-url` for the procedure.
