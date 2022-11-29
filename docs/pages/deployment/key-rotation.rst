.. _key-rotation:

Key rotation procedure
######################

.. warning::
    Rotating keys currently prevents private transactions (e.g. ``NutsAuthorizationCredential``) from being received properly:
    Do not use this functionality until the `issue has been resolved <https://github.com/nuts-foundation/nuts-node/issues/1688>`_.

To minimize the impact of stolen/leaked keys, private keys should be rotated at a regular, scheduled interval.
This applies to any (vendor, care organization, or any other) private key used for a longer period of time.
The node aids this procedure by supporting operations to add and remove keys from DID documents.

Procedure
*********

The procedure to rotate a key is as follows:

1. find out the ID of the key to rotate,
2. register a new key (verification method in the DID document)
3. remove the previous key from the DID document

To do this you need the following:

- DID of the DID document which contains the key
- the allowed usage of the key (verification method relationships)

The examples below use the CLI to perform the key rotation, but the same process can be performed using the REST API.
Each step below notes the corresponding REST API operation (refer to its documentation for the exact usage).

1. Determine which key to rotate
=============================

First, you need to determine which key you'll rotate. You either have a system to administer to schedule key rotations (recommended),
or you have to resolve the DID document to lookup the ID of the key, e.g. (given the DID ``<DID>``):

.. code-block:: shell

    nuts vdr resolve <DID>

Use the result to lookup the ID of key (verification method) to rotate, e.g.:

.. code-block:: json
    {
      ...
      "verificationMethod": [
        {
          "controller": "did:nuts:Gjkkn5PgY3hEbKBJe5xot2mGcpD7MVN9Cs4j2XU7wZZp",
          "id": "did:nuts:Gjkkn5PgY3hEbKBJe5xot2mGcpD7MVN9Cs4j2XU7wZZp#wPB7g3ipPKastvXiLJOITdCqLFDn4nJRFsCNVxaI1us",
          "type": "JsonWebKey2020"
          ...
        }
      ]
      ...
    }

The ID of the key to be rotated in the example above is (note the ``#`` sign):

.. code-block::

    did:nuts:Gjkkn5PgY3hEbKBJe5xot2mGcpD7MVN9Cs4j2XU7wZZp#wPB7g3ipPKastvXiLJOITdCqLFDn4nJRFsCNVxaI1us


Corresponding REST API operation: ``GET /internal/vdr/v1/did/{did}``

2. Register a new key
==================

Then, you add a new key which generates a new key pair in your crypto storage and adds it to the DID document:

.. code-block:: shell

    nuts vdr addvm <DID>

When successful, it returns the verification method that was added to the DID document.

Corresponding REST API operation: ``POST /internal/vdr/v1/did/{did}/verificationmethod``

.. note::

    The usage (verification method relationships) of the new key is the same, as the default usage for the key of a new DID document.
    Default key usage is sufficient for the processes supported by the Nuts node (e.g., creating access tokens, updating DID documents, or sending/receiving private transactions).
    Specifying other usages is only possible using the REST API.


3. Remove previous key
===================

The final step is to remove the previous key, which ID you determined in the first step, from the DID document.

.. code-block:: shell

    nuts vdr delvm <DID> <KEY ID>

When successful, it reports the following:

.. code-block::

    Verification method deleted from the DID document

Future operations using the DID document's keys (e.g. document updates) can now use the new key. The old key can't be used any more.

Corresponding REST API operation: ``DELETE /internal/vdr/v1/did/{did}/verificationmethod/{key-id}``