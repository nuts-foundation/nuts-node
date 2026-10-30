// Combines the Nuts Node OpenAPI specs into one document, so the API reference shows all APIs in one menu.
// This runs in the browser, so building the docs needs no extra tools and no generated spec is committed.
// It parses YAML with the global jsyaml, which scalar.js loads.

// In menu order, under two headings: APIs and Deprecated. The names say DEPRECATED as well, for tools that
// ignore the headings (x-tagGroups), like Postman.
const apis = [
    {file: "auth/v2.yaml", name: "Auth (v2)", slug: "auth-v2"},
    {file: "crypto/v1.yaml", name: "Crypto", slug: "crypto"},
    {file: "discovery/v1.yaml", name: "Discovery Service", slug: "discovery"},
    {file: "monitoring/v1.yaml", name: "Monitoring", slug: "monitoring"},
    {file: "vcr/vcr_v2.yaml", name: "Verifiable Credential Registry (v2)", slug: "vcr-v2"},
    {file: "vdr/v2.yaml", name: "Verifiable Data Registry (v2)", slug: "vdr-v2"},
    {file: "auth/v1.yaml", name: "Auth (v1) - DEPRECATED", slug: "auth-v1", deprecated: true},
    {file: "didman/v1.yaml", name: "DID Manager - DEPRECATED", slug: "didman", deprecated: true},
    {file: "network/v1.yaml", name: "Network - DEPRECATED", slug: "network", deprecated: true},
    {file: "vdr/v1.yaml", name: "Verifiable Data Registry (v1) - DEPRECATED", slug: "vdr-v1", deprecated: true},
];
// The operations a path can have; a path can also have other fields, like parameters.
const methods = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

export async function loadNutsNodeApi() {
    // The specs live in docs/_static, the parent directory of this file.
    const url = (file) => new URL(`../${file}`, import.meta.url).href;
    const load = async (file) => {
        const response = await fetch(url(file));
        if (!response.ok) throw new Error(`${url(file)}: HTTP ${response.status}`);
        // CORE_SCHEMA keeps unquoted dates in examples as text.
        return jsyaml.load(await response.text(), {schema: jsyaml.CORE_SCHEMA});
    };
    const [sharedTypes, errorResponse, ...specs] = await Promise.all(
        ["common/ssi_types.yaml", "common/error_response.yaml", ...apis.map((api) => api.file)].map(load));

    // Scalar does not load other files, so the shared types and the error response that the specs refer to are added.
    const combined = {
        openapi: "3.0.0",
        info: {title: "Nuts Node API", version: ""}, // no version: each API has its own
        // The servers of all specs; Scalar's API client only offers the servers of the document.
        servers: [],
        paths: {},
        components: {schemas: {...sharedTypes.components.schemas}, responses: {ErrorResponse: errorResponse}},
        tags: [],
    };
    const groups = {APIs: [], Deprecated: []};
    const introductions = {APIs: [], Deprecated: []};
    const operationIds = new Set();
    for (const [index, api] of apis.entries()) {
        const suffix = api.slug.replaceAll("-", "_");
        const spec = paste(specs[index], combined.components, suffix, url(api.file));

        // Tag names include the API name: that keeps them unique ("auth" is in two APIs) and readable in tools
        // that ignore x-tagGroups, like Postman. The menu has one level of groups, so it shows an API as one tag,
        // or as one tag per tag of the API.
        const operations = Object.values(spec.paths).flatMap((item) => methods.map((method) => item[method]).filter(Boolean));
        // The menu only shows tagged operations; an operation without tags has to get one in its spec.
        const untagged = operations.find((operation) => !operation.tags?.length);
        if (untagged) throw new Error(`${url(api.file)}: operation ${untagged.operationId} has no tags`);
        const names = [...new Set(operations.flatMap((operation) => operation.tags))];
        const tag = (name) => names.length === 1 ? api.name : `${api.name}: ${name}`;
        for (const name of names) {
            const description = spec.tags?.find((declared) => declared.name === name)?.description;
            combined.tags.push({name: tag(name), ...(description && {description})});
        }
        for (const operation of operations) {
            operation.tags = operation.tags.map(tag);
            if (spec.security) operation.security ??= spec.security;
            if (operation.operationId && operationIds.has(operation.operationId)) operation.operationId += `_${suffix}`;
            operationIds.add(operation.operationId);
        }
        for (const [path, item] of Object.entries(spec.paths)) {
            if (path in combined.paths) throw new Error(`${path} is in more than one spec`);
            combined.paths[path] = item;
        }
        for (const server of spec.servers ?? []) {
            const known = combined.servers.find((existing) => existing.url === server.url);
            if (known) known.description ??= server.description;
            else combined.servers.push(server);
        }
        const group = api.deprecated ? "Deprecated" : "APIs";
        groups[group].push(...names.map(tag));
        const summary = spec.info.description?.trim().replace(/\s+/g, " ");
        introductions[group].push(`- **${api.name}** ([${api.file}](${url(api.file)}))` + (summary ? `: ${summary}` : ""));
        combined.info.license ??= spec.info.license;
    }
    combined["x-tagGroups"] = Object.entries(groups).map(([name, tags]) => ({name, tags}));
    // Lists instead of headings, which renderers would add to the menu. They link each API's own spec.
    combined.info.description = Object.entries(introductions).map(([group, lines]) => `**${group}**\n\n${lines.join("\n")}`).join("\n\n");
    return combined;
}

// Adds the components of a spec to the combined ones, and returns the spec with its references to common/ pointing
// into the combined document. A name that is already taken gets the suffix, like the TokenIntrospectionRequest that
// both Auth APIs have. All APIs use the same security scheme, so that one is shared.
function paste(spec, components, suffix, url) {
    let text = JSON.stringify(spec)
        .replaceAll('"$ref":"../common/ssi_types.yaml#/', '"$ref":"#/')
        .replaceAll('"$ref":"../common/error_response.yaml"', '"$ref":"#/components/responses/ErrorResponse"');
    const other = text.match(/"\$ref":"([^#][^"]*)"/);
    if (other) throw new Error(`${url}: unsupported reference ${other[1]}`);
    // A component that only refers to the shared type with the same name is left out.
    const own = Object.entries(spec.components ?? {}).flatMap(([type, items]) => Object.entries(items)
        .filter(([name, value]) => value?.$ref !== `../common/ssi_types.yaml#/components/${type}/${name}`)
        .map(([name]) => ({type, name, ref: `#/components/${type}/${name}`})));
    const taken = new Set(own.filter(({type, name}) => type !== "securitySchemes" && name in (components[type] ?? {})).map(({ref}) => ref));
    for (const ref of taken) text = text.replaceAll(`"${ref}"`, `"${ref}_${suffix}"`).replaceAll(`"${ref}/`, `"${ref}_${suffix}/`);
    const pasted = JSON.parse(text);
    for (const {type, name, ref} of own) (components[type] ??= {})[taken.has(ref) ? `${name}_${suffix}` : name] = pasted.components[type][name];
    return pasted;
}
