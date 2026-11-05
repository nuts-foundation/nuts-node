.. _nuts-documentation:

##################
Nuts documentation
##################

This documentation is for deploying and operating the Nuts node.
How to design a use case, implement it and integrate the Nuts node with your EHR (and background information) is on the `Nuts wiki <https://wiki.nuts.nl>`_.

.. note::

    This version of the documentation is for Nuts v6.
    It no longer describes the setup of the Nuts network required for did:nuts.
    If you're looking for information on setting up a Nuts network, please refer to the `previous version <https://nuts-node.readthedocs.io/en/v5.4/>`_.

.. toctree::
    :maxdepth: 1
    :caption: Integrating:
    :glob:

    pages/integrating/api.rst
    pages/integrating/api-authentication.rst
    pages/integrating/vc.rst
    pages/integrating/supported-protocols-formats.rst
    pages/integrating/version-incompatibilities.rst
    pages/release_notes.rst

.. toctree::
    :maxdepth: 1
    :caption: Deployment & Configuration:
    :glob:

    pages/deployment/domain.rst
    pages/deployment/configuration.rst
    pages/deployment/migration.rst
    pages/deployment/recommended-deployment.rst
    pages/deployment/clustering.rst
    pages/deployment/certificates.rst
    pages/deployment/docker.rst
    pages/deployment/storage.rst
    pages/deployment/verifiable-credentials.rst
    pages/deployment/logging.rst
    pages/deployment/monitoring.rst
    pages/deployment/cli-reference.rst
    pages/deployment/discovery.rst
    pages/deployment/policy.rst
    pages/deployment/key-rotation.rst
    pages/deployment/audit-logging.rst
    pages/deployment/oauth.rst
    pages/deployment/security-considerations.rst

.. toctree::
    :maxdepth: 1
    :caption: Technology:
    :glob:

    pages/technology/**


.. toctree::
    :maxdepth: 1
    :caption: Development:
    :glob:

    pages/development/**
    pages/contribute.rst


.. toctree::
    :maxdepth: 1
    :caption: Other:
    :glob:

    pages/contact.rst
