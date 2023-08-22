package v2

// authzResponse is the response to an Authorization Code flow request.
type authzResponse struct {
	// html is the HTML page to be rendered to the user.
	html []byte
}
