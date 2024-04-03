.. _nuts-node-api:

API Reference
=============
Common Schemas and Responses: `SSI types <../../_static/common/ssi_types.yaml>`_, `Default Error <../../_static/common/error_response.yaml>`_

.. raw:: html

    <div id="swagger-ui"></div>

    <script src='../../_static/js/swagger-ui-bundle-3.52.3.js' type='text/javascript'></script>
    <script src='../../_static/js/swagger-ui-standalone-preset-3.52.3.js' type='text/javascript'></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                "dom_id": "#swagger-ui",
                urls: [
                    {url: "../../_static/auth/iam.yaml", name: "Auth (v2)"},
                    {url: "../../_static/crypto/v1.yaml", name: "Crypto"},
                    {url: "../../_static/discovery/v1.yaml", name: "Discovery Service"},
                    {url: "../../_static/monitoring/v1.yaml", name: "Monitoring"},
                    {url: "../../_static/vcr/vcr_v2.yaml", name: "Verifiable Credential Registry (v2)"},
                    {url: "../../_static/vdr/v2.yaml", name: "Verifiable Data Registry (v2)"},
					{url: "../../_static/auth/v1.yaml", name: "Auth (v1) - DEPRECATED"},
                    {url: "../../_static/didman/v1.yaml", name: "DID Manager - DEPRECATED"},
                    {url: "../../_static/network/v1.yaml", name: "Network - DEPRECATED"},
                    {url: "../../_static/vdr/v1.yaml", name: "Verifiable Data Registry (v1) - DEPRECATED"},
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
