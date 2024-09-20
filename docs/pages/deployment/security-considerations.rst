.. _security-considerations::

Security Considerations
#######################

Please consult the topics below for various security considerations.

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