package issuer

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0/client"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
)

var _ Publisher = (*oidc4vciPublisher)(nil)

type oidc4vciPublisher struct {
	//ServiceResolver didservice.ServiceResolver
}

func (o oidc4vciPublisher) PublishCredential(ctx context.Context, verifiableCredential vc.VerifiableCredential, public bool) error {
	subject, err := o.getSubjectDID(verifiableCredential)
	if err != nil {
		return err
	}
	log.Logger().Infof("Publishing credential for subject %s using OIDC4VCI", subject)

	// TODO: Lookup Credential Wallet Client Metadata. For now, we use the local node
	c, err := client.NewClient("http://localhost:1323")
	if err != nil {
		return err
	}

	// Lookup Credential Issuer Identifier in VC issuer's DID Document,
	// this is sent to the wallet in the Credential Offer, so the wallet can resolve the Credential Issuer Metadata
	// (by adding /.well-known/.... to the URL). For now, short circuit this because we have 1 node in the prototype.
	offer := oidc4vci_v0.CredentialOffer{
		CredentialIssuer: "http://localhost:1323/identity/" + verifiableCredential.Issuer.String(),
		Credentials:      nil,
		Grants:           nil,
	}

	c.ReceiveCredentialOffer(ctx, subject, &client.ReceiveCredentialOfferParams{
		CredentialOffer: "",
	})
}

func (o oidc4vciPublisher) getSubjectDID(verifiableCredential vc.VerifiableCredential) (string, error) {
	type subjectType struct {
		ID string `json:"id"`
	}
	var subject subjectType
	err := verifiableCredential.UnmarshalCredentialSubject(&subject)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal credential subject: %w", err)
	}
	if len(subject.ID) == 0 {
		return "", errors.New("missing subject ID")
	}
	return subject, err
}

func (o oidc4vciPublisher) PublishRevocation(ctx context.Context, revocation credential.Revocation) error {
	//TODO implement me
	panic("implement me")
}
