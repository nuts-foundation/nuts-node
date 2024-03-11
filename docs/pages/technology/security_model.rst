.. _security-model:

Security Model
##############

This document is aimed at the following readers:

- Developers who want to contribute to the Nuts node: which security aspects they need to consider and which not.
- Operators who want to deploy the Nuts node: which security aspects are covered by the Nuts node, and which need to be addressed somewhere else.
- Security officers who need to assess the Nuts node: to get a view on how security is handled in the Nuts node.

The Nuts node's security model aims to provide non-repudiation of operations invoked by clients, integrity and confidentiality of data.

It focuses on:

- interactions of users (e.g. system administrators) and applications (e.g. an EHR) of the vendor with the Nuts node APIs,
- security of assets managed by the Nuts node (e.g. private keys).

It does not cover interactions between Nuts nodes and systems specified by the `Nuts specifications <https://nuts-foundation.gitbook.io/drafts/>`_;
these are covered in the Nuts Start Architecture or respective RFCs.
It also does not cover interactions specified by Nuts use cases: security should be addressed in the respective Bolt specification.

Threat Model
************

The following are part of the threat model:

- Protecting against accidental (unsafe) misconfiguration of the Nuts node.
   - The system should help operators setup safe configuration, by enforcing secure defaults and hard-failing for incorrect (e.g. misspelled) configuration.
   - Implemented by:
      - Providing secure defaults for configuration.
      - Providing "strict mode" which disallows unsafe configuration.
- Protecting against leaking private key material.
   - Private keys should be kept secure, since a leak compromises a vendor's presence on the Nuts network.
   - Implemented by:
      - Storing keys in a secure storage (e.g. Hashicorp Vault).
      - Not allowing private keys to be exported, only to be created and used (signing/encrypting).
- Protecting against eavesdropping and tampering of network traffic between Nuts nodes.
   - Implemented by:
      - Using TLS for all network traffic.
      - Signing network transactions.
      - Only exchanging private transactions with authorized nodes, part of that transaction.
- Protecting against eavesdropping and tampering of external network traffic between API clients and Nuts node.
   - Implemented by:
      - Providing documentation on how to configure TLS for external traffic.
      - Only connecting to external interfaces over TLS.
- Protecting against repudiation.
   - Administrative actions, data alterations and usage of private keys must be accountable.
   - Implemented by:
      - Writing these events to the audit log.

The following are not part of the threat model:

- Protecting against unauthorized database access.
   - If an attacker can inject/modify Nuts node database records (e.g. verifiable credentials), confidentiality of EHR data might be compromised.
- Protecting against arbitrary access to the Nuts node host machine.
   - If an attacker has root access, integrity of configuration is lost and the attacker can alter security settings (e.g. inject authorized API client keys).
   - Why don't we protect against it:
     - In such circumstances, the attacker can use the system as stepping stone to attack other systems, e.g. the key storage or the EHR system.
       This makes mitigation unfeasible: there's always another way the compromised system can be exploited.
     - High cost: requires implementation in a language that provides full control over application memory (e.g. C, C++ or Rust).
     - Unpractical: requires hardening of host OS to avoid memory dumps/debugging, which is not feasible for all some environments (cloud, Windows).
- Protecting against inspection of the Nuts node process.
   - If an attacker can inspect the memory of the Nuts node process, confidentiality might be private keys lost.
   - Why don't we protect against it: same reasons as for an attacker with root access.
- Protecting against eavesdropping and tampering of internal network traffic between reverse proxy and Nuts node.
   - Why don't we protect against it:
      - It's highly dependent on the deployment environment.
      - It can still be implemented by the operator.
- Protecting against denial of service (DoS) attacks on interfaces that use HTTP.
   - If an attacker can execute expensive operation on HTTP interfaces, it could cause unavailability of the Nuts node.
   - Why don't we protect against it:
      - It's highly dependent on the deployment environment.
      - This is typically handled by existing DoS protection measures (e.g. in reverse proxy) of the operator.

External threats
^^^^^^^^^^^^^^^^

A typical Nuts Node deployment consists of various parts:

- External API clients:
   - Remote vendor's EHR system
   - IRMA mobile app
- Internal API clients:
   - Vendor's EHR and administrative system
   - Monitoring system
- Reverse proxy for HTTP and gRPC traffic (terminates TLS)
- Nuts Node
- Data stores:
   - Network data
   - Private key storage

External actors are remote Nuts nodes, remote EHR systems and IRMA mobile devices.
Remote Nuts nodes and EHR systems require a trusted TLS client certificate,
which makes an attack complex: you need to either steal an organizations certificate (very hard),
or buy a certificate using your own name (accountable, expensive, and time-consuming, depending on the certificate).
Then, when the attacker is identified, the certificate can be banned and the legal entity (holder of the certificate) could be held accountable.

The IRMA mobile app is different; it does not get authenticated, so attacks can come from anywhere/anyone.
Since there are no authentication credentials that can be revoked, attackers can only be stopped by blocking IP addresses or other typical (D)DoS mitigation techniques.

The Nuts node itself does not protect against DoS attacks; the proxy infrastructure routing external traffic to the node will have to protect against this.

Internal threats
^^^^^^^^^^^^^^^^

Internal traffic to the Nuts node does not, by default, use TLS to protect against eavesdropping or tampering.
It does allow token authentication to be configured (strongly suggested) to protect against unauthorized access and making sure API operations are accountable.

It's not possible to export private keys from the Nuts Node through the APIs: it only allows usage of keys (signing/encrypting), not exporting them.
