.. _changing-base-url:

Changing the node's base URL
#############################

Changing the node's ``url`` (see :ref:`Options <nuts-node-config>`) is basically the same as setting up a new node on a new URL.
All DIDs, VerifiableCredentials, Revocations, and other data is no longer usable.
You will not be able to revoke credentials. This means that all credentials issued under the old URL can no longer be trusted.
Actions should be taken to remove any trust that might have been established in your old identity.

As an issuer, you'll have to run the new URL side-by-side with the old URL for some time.

.. note::

    How long you should run the old URL side-by-side with the new URL depends on the use case and the validity of the credentials.
    As a rule of thumb, credentials should be renewed once a year, so you should run the old URL side-by-side with the new URL for at least a year.

As a holder, you'll have to generate DIDs for all your tenants and have issuers re-issue credentials.
This might involve a lot of manual work from your tenants.

As a verifier, nothing changes.
