.. _nuts-node-api:

Nuts APIs
=========

.. raw:: html

    <div id="swagger-ui"></div>

    <script src='../../_static/js/swagger-ui-bundle-3.18.3.js' type='text/javascript'></script>
    <script src='../../_static/js/swagger-ui-standalone-preset-3.18.3.js' type='text/javascript'></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                "dom_id": "#swagger-ui",
                urls: [
                    {url: "../../_static/nuts-example.yaml", name: "example"},
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
