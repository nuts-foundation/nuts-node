.. _nuts-node-api:

Nuts Node APIs
==============

Below you can discover the Nuts Node APIs and download their OpenAPI specifications:

- `DID Manager <../_static/didman/v1.yaml>`_
- `Crypto <../_static/crypto/v1.yaml>`_
- `Verifiable Credential Registry <../_static/vcr/v1.yaml>`_
- `Verifiable Data Registry <../_static/vdr/v1.yaml>`_
- `Network <../_static/network/v1.yaml>`_
- `Auth <../_static/auth/v1.yaml>`_

.. raw:: html

    <div id="swagger-ui"></div>

    <script src='../_static/js/swagger-ui-bundle-3.18.3.js' type='text/javascript'></script>
    <script src='../_static/js/swagger-ui-standalone-preset-3.18.3.js' type='text/javascript'></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                "dom_id": "#swagger-ui",
                urls: [
                    {url: "../_static/didman/v1.yaml", name: "DID Manager"},
                    {url: "../_static/crypto/v1.yaml", name: "Crypto"},
                    {url: "../_static/vcr/v1.yaml", name: "Verifiable Credential Registry"},
                    {url: "../_static/vdr/v1.yaml", name: "Verifiable Data Registry"},
                    {url: "../_static/network/v1.yaml", name: "Network"},
                    {url: "../_static/auth/v1.yaml", name: "Auth"},
                    ],
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                layout: "StandaloneLayout"
            });

            window.ui = ui
        }

    </script>
