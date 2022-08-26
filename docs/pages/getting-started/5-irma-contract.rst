.. _irma-contract:

Signing a contract with IRMA
############################

This getting started manual shows how to successfully use IRMA to sign a contract.
Contracts are used within the Nuts ecosystem to identify a user to other network participants.
It also relates a user to the care organization that user is currently working for.
The signed contract is used as token to authenticate the user's (local) EHR identity to other nodes in the network and can be used as session token on the EHR.
The contract is required for every request that results in personal and/or medical data being retrieved.

Basic requirements
******************

To use IRMA as a means for signing a contract, the following is required:

- the user has the IRMA app installed on an Android or iOS device with camera and an internet connection.
- the user has retrieved the BRP and email credentials in the IRMA app.
- the user interacts with the XIS/ECD via a recent browser capable of running javascript.
- the vendor has a Nuts node running.

IRMA flow
*********

We use the Nuts node as IRMA server and as tool to start an IRMA session. This follows the flow as described on this `IRMA Github page <https://github.com/privacybydesign/irma-frontend-packages#supported-irma-flows>`_.
The XIS/ECD will have to provide two endpoints for the frontend. One endpoint to start a session and one to get the session result.
More info on these endpoints will be provided further down.


Configuring the Nuts node
*************************

In the contract signing flow, the device running the IRMA app communicates with the Nuts node directly.
Therefore the Nuts node needs to be accessible to the public internet.
All APIs on the Nuts node starting with ``/public`` (without a trailing slash) must be accessible over HTTPS without any additional security measures that could prevent access by mobile devices.
A domain must also be available which resolves to those APIs.
The domain must be configured on the Nuts node:

.. code-block:: yaml

  auth:
    publicurl: https://example.com

The Nuts APIs used for signing will embed this URL in the QR code shown to the user.
The javascript in the frontend will also use this URL (exposed via the QR code) to check the status of the signing session.
Therefore the domain which serves the frontend must be able to do requests to that domain.
The browser will require CORS headers to be configured on the domain configured in the Nuts node config.
This can be done by the following snippet:

.. code-block:: yaml

  http:
    default:
      cors:
        origin: "other.com"

Where *other.com* is the domain serving the frontend. For development purposes ``*`` is also allowed.
If the public APIs are mounted on a different port/interface in the nuts config then the ``default`` key should be changed to ``alt.public`` in the example above.

Setting up the frontend
***********************

For the frontend we'll be using the `irma-frontend-packages <https://github.com/privacybydesign/irma-frontend-packages>`_ javascript library.
More info on how to use this library can be found on `<https://irma.app/docs/irma-frontend/>`_.
You can choose to load the IRMA frontend packages javascript via an HTML tag, in which case you'll need to build the javascript file yourself given the instructions on `<https://github.com/privacybydesign/irma-frontend-packages>`_ or you can choose to use ``npm``:

.. code-block:: json

  "dependencies": {
    "@privacybydesign/irma-frontend": "^0.3.3"
  }

Make sure you use the latest version.

IRMA allows for multiple frontends to be used. The most important ones are the *web* and *popup* frontends.
The *web* frontend allows for embedding the IRMA web component within a html element.
The *popup* frontend will render a new component that will render on top of the rest of the website.
This manual will use the *popup* frontend.

A complete example:

.. code-block:: javascript

  let options = {
        // Developer options
        debugging: true,

        // Front-end options
        language: 'en',

        // customize textual components
        translations: {
          header: "Sign your contract"
        },

        // Back-end options
        session: {
          // Point to your web backend
          url: '/web/auth',

          // The request that will be send to the backend:
          start: {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(this.some_data)
          },

          // required to translate Nuts specific return values
          mapping: {
            sessionPtr:      r => r.sessionPtr.clientPtr,
            sessionToken:    r => r.sessionID
          }
        }
      };

      // we'll use the popup frontend
      let irmaPopup = irma.newPopup(options);

      // start the interaction
      irmaPopup.start()
          .then(result => {
            console.log("success!")
            console.log(response)
          })
          .catch(error => {
            if (error === 'Aborted') {
              console.log('Aborted');
              return;
            }
            console.error("error", error);
          })
          .finally(() => irmaPopup = irma.newPopup(options));
    }

Lets break this down into parts.

.. code-block:: javascript

    // Developer options
    debugging: true,

Is used to enabling debugging. The IRMA library will output more information helpful for development.

.. code-block:: javascript

    // Front-end options
    language: 'en',

    // customize textual components
    translations: {
      header: "Sign your contract"
    },

Sets the language to english which will set some default textual representations on the IRMA web component.
The ``translations`` configuration option can be used to change each of the textual representation on the IRMA web component.
In this case, only the header is changed.

.. code-block:: javascript

    // Back-end options
    session: {
      // Point to your web backend
      url: '/web/auth',

      // The request that will be send to the backend:
      start: {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(this.some_data)
      },

      // required to translate Nuts specific return values
      mapping: {
        sessionPtr:      r => r.sessionPtr.clientPtr,
        sessionToken:    r => r.sessionID
      }
    }

The ``session`` object contains all the technical parts to connect the IRMA javascript library to your backend.
The contents of the ``start`` object configures the initial request to start a signing session. You can control the type of request and the contents.
In this case, some data from the frontend is sent as JSON. This is optional and no particular data is required.
The ``url``, in this case ``/web/auth``, must be set so the frontend can access the following URLs:

.. code-block::

    <url>/session
    <url>/session/<sessionToken>/result

These URLs must both be available on the backend. For the example above this means that both ``/web/auth/session/`` and ``/web/auth/session/<sessionToken>/result`` are available. The ``<sessionToken>`` is the token that will be returned by the call to ``<url>/session/``.
How to parse the result of that call and extract the token is done via the ``mapping`` object.

The ``mapping`` object is a map where two keys are expected: ``sessionPtr`` and ``sessionToken``.
``sessionPtr`` must point to the data that is used to render the QR code.
``sessionToken`` must point to the session token used to get the result.

Setting up the backend
**********************

As discussed in the previous chapter, the backend is required to expose two APIs to the frontend:

.. code-block::

    <url>/session
    <url>/session/<sessionToken>/result

No particular security context is required, you may require a user session if needed.

Starting a session
==================

The ``<url>/session`` API is used to start a session.
To start a session at the Nuts node, a valid contract has to be drawn up first.
You can create such a contract with the following API on the Nuts node:

.. code-block::

    PUT /internal/auth/v1/contract/drawup

With the following body:

.. code-block:: json

    {
      "type": "BehandelaarLogin",
      "language": "NL",
      "version": "v3",
      "legalEntity": "did:nuts:90348275fjasihnva4857qp39hn",
      "validFrom": "2006-01-02T15:04:05+02:00",
      "validDuration": "2h"
    }

The ``type`` must be one of the valid Nuts contract types, currently only ``BehandelaarLogin`` for Dutch and ``PractitionerLogin`` for English are supported.
The ``language``` selects the correct language, ``NL`` for Dutch and ``EN`` for english. The ``version`` must be ``v3``.
The ``legalEntity`` must refer to the DID of the current organization. The user either selects an organization to login for, or is already logged in.
The organization must have a DID as described in :ref:`Getting Started on customer integration <connecting-crm>`.
``validFrom`` is a RFC3339 compliant time string. ``validDuration`` describes how long the contract is valid for. Time unit strings are used like ``1h`` or ``60m``, the valid time units are: "ns", "us" (or "µs"), "ms", "s", "m", "h". The local system timezone is used to format the date and time string.

The return value looks like:

.. code-block:: json

    {
      "type": "PractitionerLogin",
      "language": "EN",
      "version": "v3",
      "message": "EN:PractitionerLogin:v3 I hereby declare to act on behalf of CareBears located in CareTown. This declaration is valid from Monday, 2 January 2006 15:04:05 until Monday, 2 January 2006 17:04:05."
    }

The ``message`` from this result is used in the next part.
Start an IRMA session by calling the following API on the Nuts node:

.. code-block::

    POST /internal/auth/v1/signature/session

The body for this call looks like:

.. code-block:: json

    {
        "means": "irma",
        "payload": "<message>"
    }

Where ``message`` is the result from the contract call.
The result from this call must be passed directly to the frontend.
If any transformation is done, the ``mapping`` setting in the frontend must be changed accordingly.

Getting the session result
==========================

The IRMA javascript frontend library will check for the status of the signing session. When the session has been completed it'll call the following url:

.. code-block::

    GET <url>/session/<sessionToken>/result

where ``<url>`` is the base url configured under ``session.url`` in the javascript options and ``<sessionToken>`` is the token returned by the previous call.
The backend must implement this API, the implementation must call the following API on the Nuts node:

.. code-block::

    GET /internal/auth/v1/signature/session/<sessionToken>

Any error in calling this service need to be relayed to the frontend. This will instruct the user on why things went wrong and what to do next.
The call to the Nuts node will return the following response:

.. code-block:: json

    {
        "status": "completed",
        "verifiablePresentation": {
            // ...
        }
    }

The ``status`` field has a different content when a different signing means is used.
The presence of the ``verifiablePresentation`` in the result is the main method of checking if the signing session succeeded.
``verifiablePresentation`` is the cryptographic proof that needs to be stored in the user session.
It's required in the OAuth flow for obtaining an access token.
The backend should check if the signed contract (verifiable presentation) is still valid when using it.
The validity can be checked by calling the following API with the verifiable presentation at the place of ``<vp>``:

.. code-block::

    PUT /internal/auth/v1/signature/verify

with

.. code-block:: json

    {
        "checkTime": "2006-01-02T15:54:05+02:00",
        "verifiablePresentation": "<vp>"
    }


It will return a structure similar to:

.. code-block:: json

    {
      "validity": true,
      "vpType": "NutsIrmaPresentation",
      "issuerAttributes": {
        "pbdf.gemeente.personalData.initials": "T",
	    "pbdf.gemeente.personalData.prefix": "",
	    "pbdf.gemeente.personalData.familyname": "Tester",
	    "pbdf.sidn-pbdf.email.email": "tester@example.com"
      },
      "credentials": {
        "organization": "CareBears",
        "validFrom": "2006-01-02T15:04:05+02:00",
        "validTo": "2006-01-02T17:04:05+02:00"
      }
    }

The ``validity`` will indicate its validity. An expired contract is considered invalid.
