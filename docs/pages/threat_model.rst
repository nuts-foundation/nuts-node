Threat Model
############

The list belows follows the `STRIDE <https://en.wikipedia.org/wiki/STRIDE_(security)>`_ methodology of identifying threats.

.. note::

     Arguing whether a specific threat falls in category X or Y is time wasted: many fall in more than one category,
     and it's not meant as a perfect taxonomy. Focus on finding threats instead.

Threats can be handled in 3 ways:

- Mitigated (e.g. by fixing bugs)
- Eliminated (e.g. by eliminating a feature)
- Accepted

Spoofing
********

Tampering
*********

Repudiation
***********

Information Disclosure
**********************

Denial of Service
*****************

.. list-table::
    * - Status
      - Resolution
      - Threat
    * - ⚠
      -
      - Network Protocol: an attacker may cause high resource consumption by returning/gossiping transactions with non-existing ``prev``s.

Elevation of Privilege
**********************
