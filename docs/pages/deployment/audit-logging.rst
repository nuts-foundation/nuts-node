.. _audit-logging:

Audit Logging
#############

.. note ::
    This feature is under development, not all relevant operations might be included in the audit log.

Important events are logged as audit events. Examples are creation of a new cryptographic key pair or its usage when signing or decrypting.

Audit events are logged to application log and can be recognized by the ``audit`` log level.
In addition, the events contain the following fields:

- ``operation`` which contains name action that was performed
- ``actor`` which contains the name of the user/system that performed the action.

To redirect the audit log to safe storage, it is advised to use a log processor (e.g. `Fluentbit <https://fluentbit.io/>`_).
You can use the ``audit`` log level to detect audit logs and redirect it to a separate log collector.