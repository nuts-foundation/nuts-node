.. _running-docker:

"Hello World" on Docker
#######################

.. marker-for-readme

The simplest way to spin up the Nuts stack is by using the setup provided by `nuts-network-local <https://github.com/nuts-foundation/nuts-network-local>`_.
The setup is meant for development purposes and starts a Nuts node, "Demo EHR", "Registry Admin Demo" for administering your vendor and care organizations and a HAPI server to exchange FHIR data.

To get started, clone the repository and run the following commands to start the stack:

.. code-block:: shell

    cd single
    docker compose pull
    docker compose up

After the services have started you can try the following endpoints:

- `Nuts Node status page <http://localhost:1323/status/diagnostics/>`_.
- `Registry Admin Demo login <http://localhost:1304/>`_ (default password: "demo").
- `Demo EHR login <http://localhost:1303/>`_ (default password: "demo").
