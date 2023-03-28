package oidc4vci

import "github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0/types"

// WalletClient defines the API client used by the credential issuer to communicate with the receiving wallet.
type WalletClient interface {
	// OfferCredential sends a credential offer to the wallet. If the delivery fails an error is returned.
	OfferCredential(offer types.CredentialOffer) error
}

// WalletMetadata defines the metadata of the wallet.
type WalletMetadata struct {
	OfferEndpoint string
}

// NewWalletClient resolves the client metadata URL and returns a client that can be used to communicate with the wallet.
func NewWalletClient(clientMetadataURL string) (WalletClient, error) {
	panic("implement me")
}

func NewWalletClientFromMetadata(md WalletMetadata) (WalletClient, error) {
	panic("implement me")
}
