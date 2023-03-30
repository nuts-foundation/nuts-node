package issuer

import (
	"context"
	"errors"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
)

var _ Publisher = (*OIDC4VCIPublisher)(nil)

type OIDC4VCIPublisher struct {
	IssuerRegistry *oidc4vci.IssuerRegistry
}

func (o OIDC4VCIPublisher) PublishCredential(ctx context.Context, verifiableCredential vc.VerifiableCredential, _ bool) error {
	// TODO (non-prototype): currently, the verifiable credential is already fully created before and stored as issued credential,
	//                       before the exchange with the wallet happens. This means we don't have asserted proof-of-possession of the private key from the wallet.
	//                       We need to assess the actual risks of this.
	//                       Also, it's not known beforehand whether the wallet will ever actually retrieve the verifiable credential.
	//                       Cleaner (and securer) would be to create the Verifiable Credential only when the wallet actually requests it.
	// TODO: This a bit of a hack, but it works. We need to find a better way to pass the wallet metadata URL to the publisher.
	walletMetadataURL, ok := ctx.Value("wallet-metadata-url").(string)
	if !ok {
		return errors.New("wallet-metadata-url not set in context")
	}
	return o.IssuerRegistry.Get(verifiableCredential.Issuer.String()).Offer(ctx, verifiableCredential, walletMetadataURL)
}
func (o OIDC4VCIPublisher) PublishRevocation(ctx context.Context, revocation credential.Revocation) error {
	//TODO implement me
	panic("implement me")
}
