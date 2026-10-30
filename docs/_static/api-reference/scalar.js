// Renders the Nuts Node API reference with Scalar; shared by the embedded and the full-screen page.
import {loadNutsNodeApi} from "./nuts-node-api.js";

// Exact npm versions, checked with Subresource Integrity. cdnjs serves the same files when jsDelivr is unavailable.
const scripts = [
    {
        integrity: "sha384-+pxiN6T7yvpryuJmE1gM9PX7yQit15auDb+ZwwvJOd/4be2Cie5/IuVXgQb/S9du",
        urls: [
            "https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.min.js",
            "https://cdnjs.cloudflare.com/ajax/libs/js-yaml/4.1.0/js-yaml.min.js",
        ],
    },
    {
        integrity: "sha384-mCh2A/B6vkfhiHyzwBZm7lbFmEK5fE/96Kbtk+RH1zei1P/XEt0I2MCiG6WfZdor",
        urls: [
            "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.76.2/dist/browser/standalone.js",
            "https://cdnjs.cloudflare.com/ajax/libs/scalar-api-reference/1.76.2/standalone.js",
        ],
    },
];

export async function renderNutsApiReference(selector) {
    const element = document.querySelector(selector);
    try {
        await Promise.all(scripts.map(load));
        Scalar.createApiReference(element, {
            content: await loadNutsNodeApi(),
            // Scalar's hosted AI chat only appears on localhost; keep it off everywhere.
            agent: {disabled: true},
            showDeveloperTools: "never",
        });
    } catch (error) {
        element.textContent = `The API reference could not be loaded: ${error.message}`;
        throw error;
    }
}

// Loads a script from the first of its URLs that works.
async function load({integrity, urls}) {
    for (const src of urls) {
        const loaded = await new Promise((resolve) => {
            const script = Object.assign(document.createElement("script"), {src, integrity, crossOrigin: "anonymous"});
            script.onload = () => resolve(true);
            script.onerror = () => {
                script.remove();
                resolve(false);
            };
            document.head.append(script);
        });
        if (loaded) return;
    }
    throw new Error(`${urls[0]} could not be loaded`);
}
