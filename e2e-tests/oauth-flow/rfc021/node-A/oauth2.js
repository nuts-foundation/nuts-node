function introspectAccessToken(r) {
    // strip the first 8 chars
    var token = "token=" + r.headersIn['Authorization'].substring(7);
    // make a subrequest to the introspection endpoint
    r.subrequest("/_oauth2_send_request",
        { method: "POST", body: token },
        function(reply) {
            if (reply.status == 200) {
                var introspection = JSON.parse(reply.responseBody);
                if (introspection.active) {
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