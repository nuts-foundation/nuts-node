package oidc4vci_v0

import (
	"context"
	"github.com/nuts-foundation/nuts-node/auth/oidc4vci"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
)

// TODO: Split this file into multiple files, per role (issuer/holder)

var _ StrictServerInterface = (*Wrapper)(nil)

type Wrapper struct {
	Issuer          *oidc4vci.Issuer
	CredentialStore vcr.Writer
}

func (w Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, nil))
}

func (w Wrapper) GetOIDCProviderMeta(ctx context.Context, request GetOIDCProviderMetaRequestObject) (GetOIDCProviderMetaResponseObject, error) {
	// TODO (non-prototype): we route the OpenID Connect Provider Metadata endpoint to the OIDC4VCI Credential Issuer Metadata endpoint,
	//                       since the fields don't clash, and the added complexity of a second endpoint is currently not worth it.
	//                       Clients will simply retrieve the same data twice.
	metadata := w.getOIDCIssuerMetadata(request.Did)
	return GetOIDCProviderMeta200JSONResponse(metadata), nil
}
