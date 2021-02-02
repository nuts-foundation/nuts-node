.. _nuts-node-config:

Nuts node config
################

.. marker-for-readme

The Nuts library contains some configuration logic which allows for usage of configFiles, Environment variables and commandLine params transparently.

The parameters follow the following convention:
``$ nuts --parameter X`` is equal to ``$ NUTS_PARAMETER=X nuts`` is equal to ``parameter: X`` in a yaml file.

Or for this piece of yaml

.. code-block:: yaml

    nested:
        parameter: X

is equal to ``$ nuts --nested.parameter X`` is equal to ``$ NUTS_NESTED_PARAMETER=X nuts``

Config parameters for engines are prepended by the ``engine.ConfigKey`` by default (configurable):

.. code-block:: yaml

    engine:
        nested:
            parameter: X

is equal to ``$ nuts --engine.nested.parameter X`` is equal to ``$ NUTS_ENGINE_NESTED_PARAMETER=X nuts``


Ordering
********

Command line parameters have the highest priority, then environment variables, then parameters from the configfile and lastly defaults.
The location of the configfile is determined by the environment variable ``NUTS_CONFIGFILE`` or the commandline parameter ``--configfile``. If both are missing the default location ``./nuts.yaml`` is used.

Options
*******

The following options can be configured:

.. marker-for-config-options

.. include:: options.rst

This table is automatically generated using the configuration flags in the core and engines. When they're changed
the options table must be regenerated using the Makefile:

.. code-block:: shell

    $ make update-docs