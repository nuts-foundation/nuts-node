.. _nuts-node-api:

API Reference
=============
Common Schemas and Responses: `SSI types <../../_static/common/ssi_types.yaml>`_, `Default Error <../../_static/common/error_response.yaml>`_

.. raw:: html

    <p style="text-align: right"><a id="scalar-full-screen" class="fa fa-external-link" href="../../_static/api-reference/scalar.html" target="_blank" title="Open full screen" aria-label="Open full screen"></a></p>
    <style>
        /* Use the full width; style.css limits pages to 1000px. */
        .wy-nav-content { max-width: none !important; }
        /* The theme hides .hidden with !important, which also hides Scalar's menu and search ("hidden lg:flex") on wide screens. */
        @media (min-width: 1000px) { .scalar-app .hidden.lg\:flex { display: flex !important; visibility: visible; } }
    </style>
    <!-- Not id="api-reference": the Scalar script mounts an unconfigured reference into that element by itself. -->
    <div id="scalar"></div>

    <script type="module">
        import {renderNutsApiReference} from "../../_static/api-reference/scalar.js";
        renderNutsApiReference("#scalar");
        // Open the same operation in full screen.
        document.getElementById("scalar-full-screen").addEventListener("click", (event) => {
            event.currentTarget.href = event.currentTarget.href.split("#")[0] + location.hash;
        });
    </script>
