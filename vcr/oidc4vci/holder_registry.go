package oidc4vci

import vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"

// HolderRegistry is a registry of Wallet instances, used to keep track of holders in a multi-tenant environment.
type HolderRegistry struct {
	holderBaseURL   string
	credentialStore vcrTypes.Writer
}

func NewHolderRegistry(holderBaseURL string, credentialStore vcrTypes.Writer) *HolderRegistry {
	// Add trailing slash if missing
	if holderBaseURL[len(holderBaseURL)-1] != '/' {
		holderBaseURL += "/"
	}
	return &HolderRegistry{
		holderBaseURL:   holderBaseURL,
		credentialStore: credentialStore,
	}
}

func (h HolderRegistry) GetWallet(did string) Wallet {
	return &wallet{
		did:             did,
		identifier:      h.holderBaseURL + did,
		credentialStore: h.credentialStore,
	}
}
