.. _nuts-node-api:

API Reference
=============

Below you can discover the Nuts Node APIs and download their OpenAPI specifications:

- Common: `SSI types <../../_static/common/ssi_types.yaml>`_, `Default Error <../../_static/common/error_response.yaml>`_
- `DID Manager <../../_static/didman/v1.yaml>`_
- `Crypto <../../_static/crypto/v1.yaml>`_
- `Verifiable Credential Registry (v2) <../../_static/vcr/vcr_v2.yaml>`_
- `Verifiable Data Registry <../../_static/vdr/v1.yaml>`_
- `Network <../../_static/network/v1.yaml>`_
- `Auth <../../_static/auth/v1.yaml>`_
- `Monitoring <../../_static/monitoring/v1.yaml>`_

.. raw:: html

    &nbsp;

.. raw:: html

    <div id="swagger-ui"></div>

    <script src='../../_static/js/swagger-ui-bundle-3.52.3.js' type='text/javascript'></script>
    <script src='../../_static/js/swagger-ui-standalone-preset-3.52.3.js' type='text/javascript'></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                "dom_id": "#swagger-ui",
                urls: [
                    {url: "../../_static/didman/v1.yaml", name: "DID Manager"},
                    {url: "../../_static/crypto/v1.yaml", name: "Crypto"},
                    {url: "../../_static/vcr/vcr_v2.yaml", name: "Verifiable Credential Registry (v2)"},
                    {url: "../../_static/vdr/v1.yaml", name: "Verifiable Data Registry"},
                    {url: "../../_static/network/v1.yaml", name: "Network"},
                    {url: "../../_static/auth/v1.yaml", name: "Auth"},
                    {url: "../../_static/monitoring/v1.yaml", name: "Monitoring"},
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
