package auth

import (
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

func (auth *Auth) MitzXNutsIAMClient() iam.MitzXNutsClient {
	keyResolver := resolver.DIDKeyResolver{Resolver: auth.vdrInstance.Resolver()}
	return iam.NewClient(auth.vcr.Wallet(), keyResolver, auth.keyStore, auth.strictMode, auth.httpClientTimeout, auth.tlsConfig)
}
