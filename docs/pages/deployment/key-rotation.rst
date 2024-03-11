.. _key-rotation:

Key rotation procedure
######################

To minimize the impact of stolen/leaked keys, private keys should be rotated at a regular, scheduled interval.
This applies to any private key used for a longer period of time.
The node aids this procedure by supporting operations to add and remove keys from DID documents.

Removal of old keys from the DID document should only be done if there are no verifiable credentials still active.
To ensure this, all verifiable credentials should set a validity period.

Procedure
*********

The procedure to rotate a key is two fold. The two procedures can be performed independently.

Given a period of time, eg. every month when issuing a lot of credentials or every year when issuing only a few, a new key should be added to the DID document.
To remove old keys from the DID document, you need to ensure that all verifiable credentials have expired.

.. note::

	The current API doesn't support finding VCs based on validity period or specific key.
	The only possibility is to find all and loop over the results to check the validity period and the key used to sign the VC.

1. Add a new key
================

Then, you add a new key which generates a new key pair in your crypto storage and adds it to the DID document:

.. code-block:: shell

    POST /internal/vdr/v2/did/{did}/verificationmethod

When successful, it returns the verification method that was added to the DID document.

2. Remove a key
===============

To remove a key from the DID document.

.. code-block:: shell

    DELETE /internal/vdr/v2/did/{did}/verificationmethod/{kid}

When successful, it returns with a ``204`` tatus code
