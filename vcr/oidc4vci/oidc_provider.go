package oidc4vci

import "github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"

type OIDCProvider interface {
	Metadata() types.OIDCProviderMetadata
}
