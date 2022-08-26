.. _nuts-node-api-authentication:

API Authentication
==================

You can configure the Nuts Node's HTTP APIs to require authentication before allowing calls.
Refer to :ref:`Configuring for Production <production-configuration>` to find out how to configure it.

When enabled you need to pass a bearer token as ``Authorization`` header:

    Authorization: Bearer (token)

You generate a token by using the ``http gen-token`` command.
The example below generates a token for a user named "admin", valid for 3 months:

.. code-block:: shell

    nuts http gen-token admin 180

When authentication fails the API will return ``HTTP 401 Unauthorized`` with an explanatory message.