package issuer

import (
	"context"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

var _ Publisher = (*OIDC4VCIPublisher)(nil)

type OIDC4VCIPublisher struct {
	//Issuer func(ctx context.Context, credential vc.VerifiableCredential) error
	Issuer *oidc4vci.Issuer
}

func (o OIDC4VCIPublisher) PublishCredential(ctx context.Context, verifiableCredential vc.VerifiableCredential, _ bool) error {
	// TODO (non-prototype): currently, the verifiable credential is already fully created before and stored as issued credential,
	//                       before the exchange with the wallet happens. This means we don't have asserted proof-of-possession of the private key from the wallet.
	//                       We need to assess the actual risks of this.
	//                       Also, it's not known beforehand whether the wallet will ever actually retrieve the verifiable credential.
	//                       Cleaner (and securer) would be to create the Verifiable Credential only when the wallet actually requests it.
	return o.Issuer.Offer(ctx, verifiableCredential)
}
func (o OIDC4VCIPublisher) PublishRevocation(ctx context.Context, revocation credential.Revocation) error {
	//TODO implement me
	panic("implement me")
}
