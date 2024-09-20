.. _security-considerations:

Security Considerations
#######################

Please consult the topics below for various security considerations.

Endpoint Security
*****************

It's important to prevent outside access to the internal API's. By default these are available from ``127.0.0.1:8081`` and are not protected with API security.
When exposing the external APIs to your internal network, take the appropriate measures to secure the API's (SSH, API security, etc).

In addition to securing the internal APIs, it's recommended to limit access to the public APIs using a reverse proxy.
This will allow you to control access to the public APIs, do TLS termination and add additional security measures.
Block any path that's not used by the Nuts node.

D(D)oS Protection
*****************

Consider implementing (D)DoS protection on the application layer for all public endpoints.

Maximum client body size for public-facing POST APIs
****************************************************

Various parts of the Nuts Node API allow for POST requests. To prevent abuse, you should limit the size of the request body.
The following public APIs accept POST requests:

- ``/discovery/{service}``
- ``/oauth2/{subjectID}/token``
- ``/oauth2/{subjectID}/request.jwt/{id}``
- ``/oauth2/{subjectID}/response``

To prevent malicious uploads, you MUST limit the size of the requests.

For example, Nginx has a configuration directive to limit the size of the request body:

.. code-block:: nginx

    client_max_body_size 1M;

The actual limit depends on your use case. It should be large enough for Verifiable Presentations to be uploaded, but small enough to prevent abuse.

Key rotation
************

It's important to have a key rotation policy in place. The Nuts node uses keys for various signing operations.
These operations are numerous and therefore keys should be rotated regularly.