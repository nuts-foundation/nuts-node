package oidc4vci

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

// HolderRegistry is a registry of Wallet instances, used to keep track of holders in a multi-tenant environment.
type HolderRegistry struct {
	holderBaseURL   string
	credentialStore vcrTypes.Writer
	signer          crypto.JWTSigner
	resolver        vdr.KeyResolver
}

func NewHolderRegistry(holderBaseURL string, credentialStore vcrTypes.Writer, signer crypto.JWTSigner, resolver vdr.KeyResolver) *HolderRegistry {
	// Add trailing slash if missing
	if holderBaseURL[len(holderBaseURL)-1] != '/' {
		holderBaseURL += "/"
	}
	return &HolderRegistry{
		credentialStore: credentialStore,
		signer:          signer,
		resolver:        resolver,
		holderBaseURL:   holderBaseURL,
	}
}

func (h HolderRegistry) GetWallet(did did.DID) Wallet {
	return &wallet{
		did:             did,
		identifier:      h.holderBaseURL + "identity/" + did.String(),
		credentialStore: h.credentialStore,
		signer:          h.signer,
		resolver:        h.resolver,
	}
}
