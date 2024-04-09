// # check access via token introspection as described by https://www.nginx.com/blog/validating-oauth-2-0-access-tokens-nginx/
function introspectAccessToken(r) {
    // strip the first 5 chars
    var token = "token=" + r.headersIn['Authorization'].substring(5);
    // make a subrequest to the introspection endpoint
    r.subrequest("/_oauth2_send_request",
        { method: "POST", body: token},
        function(reply) {
            if (reply.status == 200) {
                var introspection = JSON.parse(reply.responseBody);
                if (introspection.active) {
                    dpop(r, introspection.cnf)
                } else {
                    r.return(403, "Unauthorized");
                }
            } else {
                r.return(500, "Internal Server Error");
            }
        }
    );
}

function dpop(r, cnf) {

    // create JSON payload
    const payload = {
        dpop: r.headersIn['DPoP'],
        method: r.method,
        thumbprint: cnf.jkt,
        token: r.headersIn['Authorization'].substring(5),
        url: r.headersIn.host + r.uri
    }
    // make a subrequest to the dpop endpoint
    r.subrequest("/_dpop_send_request",
        { method: "POST", body: JSON.stringify(payload)},
        function(reply) {
            if (reply.status == 200) {
                var introspection = JSON.parse(reply.responseBody);
                if (introspection.valid) {
                    r.return(200, "OK");
                } else {
                    r.return(403, "Unauthorized");
                }
            } else {
                r.return(500, "Internal Server Error");
            }
        }
    );
}

export default { introspectAccessToken };