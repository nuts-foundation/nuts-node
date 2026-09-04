.. _key-rotation:

Key rotation procedure
######################

To minimize the impact of stolen/leaked keys, private keys should be rotated at a regular, scheduled interval.
This applies to any private key used for a longer period of time.
The node currently only supports the "add" half of rotation: adding a new key to a DID document.
Removing an existing key is not supported — once added, a key remains part of the DID document indefinitely.
Newer keys are automatically used for cryptographic operations.

Adding a new key
*****************

Given a period of time, eg. every month when issuing a lot of credentials or every year when issuing only a few, a new key should be added to the DID document.

.. note::

	The current API doesn't support finding VCs based on validity period or specific key.
	The only possibility is to find all and loop over the results to check the validity period and the key used to sign the VC.

You add a new key, which generates a new key pair in your crypto storage and adds it to the DID document:

.. code-block:: shell

    POST /internal/vdr/v2/subject/{id}/verificationmethod

When successful, it returns the verification method(s) that were added to the DID document(s).
