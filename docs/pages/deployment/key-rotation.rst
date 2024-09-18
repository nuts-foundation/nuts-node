.. _key-rotation:

Key rotation procedure
######################

To minimize the impact of stolen/leaked keys, private keys should be rotated at a regular, scheduled interval.
This applies to any private key used for a longer period of time.
The node aids this procedure by supporting operations to add to DID documents.
Removal of keys is currently not supported. Newer keys are automatically used for cryptographic operations.

Procedure
*********

The procedure to rotate a key is two fold. The two procedures can be performed independently.

Given a period of time, eg. every month when issuing a lot of credentials or every year when issuing only a few, a new key should be added to the DID document.

.. note::

	The current API doesn't support finding VCs based on validity period or specific key.
	The only possibility is to find all and loop over the results to check the validity period and the key used to sign the VC.

1. Add a new key
================

Then, you add a new key which generates a new key pair in your crypto storage and adds it to the DID document:

.. code-block:: shell

    POST /internal/vdr/v2/{subject}/verificationmethod

When successful, it returns the verification method(s) that were added to the DID document(s).
