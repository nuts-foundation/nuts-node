package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0/client"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"net/url"
)

var _ Publisher = (*oidc4vciPublisher)(nil)

type oidc4vciPublisher struct {
	//ServiceResolver didservice.ServiceResolver
}

func (o oidc4vciPublisher) PublishCredential(ctx context.Context, verifiableCredential vc.VerifiableCredential, _ bool) error {
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
		Credentials: []map[string]interface{}{{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"@context": verifiableCredential.Context,
				"types":    verifiableCredential.Type,
			},
		}},
		Grants: map[string]interface{}{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
				"pre-authorized_code": "1234",
			},
		},
	}

	offerJson, err := json.Marshal(offer)
	if err != nil {
		return err
	}

	res, err := c.CredentialOffer(ctx, subject, &client.CredentialOfferParams{
		CredentialOffer: url.QueryEscape(string(offerJson)),
	})

	if err != nil {
		return err
	}
	if res.StatusCode > 299 {
		return fmt.Errorf("non 2xx status code: %s", res.Status)
	}
	return nil
}

func (o oidc4vciPublisher) getSubjectDID(verifiableCredential vc.VerifiableCredential) (string, error) {
	type subjectType struct {
		ID string `json:"id"`
	}
	var subject []subjectType
	err := verifiableCredential.UnmarshalCredentialSubject(&subject)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal credential subject: %w", err)
	}
	if len(subject) == 0 {
		return "", errors.New("missing subject ID")
	}
	return subject[0].ID, err
}

func (o oidc4vciPublisher) PublishRevocation(ctx context.Context, revocation credential.Revocation) error {
	//TODO implement me
	panic("implement me")
}
