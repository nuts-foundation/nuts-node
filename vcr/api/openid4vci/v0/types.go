package v0

import "github.com/nuts-foundation/nuts-node/auth/oauth"

func (r RequestAccessToken200JSONResponse) MarshalJSON() ([]byte, error) {
	return oauth.TokenResponse(r).MarshalJSON()
}
