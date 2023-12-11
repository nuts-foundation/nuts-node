package discovery

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	apiClient "github.com/nuts-foundation/nuts-node/discovery/api/v1/client"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"net/http"
)

// client is a Discovery Client that can registers Verifiable Presentations on a Discovery Service,
// and can retrieve Verifiable Presentations from a Discovery Service.
type client struct {
	documentOwner management.DocumentOwner
	wallet        holder.Wallet
	definitions   map[string]ServiceDefinition
}

// autoRegistration periodically registers Verifiable Presentations on a Discovery Service.
// It checks local wallets for Verifiable Credentials that match a service's Presentation Definition.
func (c client) autoRegistration() error {
	ctx := context.TODO()
	walletDIDs, err := c.documentOwner.ListOwned(ctx)
	if err != nil {
		return err
	}

	for _, definition := range c.definitions {
		for _, walletDID := range walletDIDs {
			// TODO: Check whether the DID is eligible for registration for this particular service
			//       Use JSONPath in the Presentation Definition's Purpose field?
			walletCredentials, err := c.wallet.List(ctx, walletDID)
			if err != nil {
				return fmt.Errorf("failed to list credentials for DID %s: %w", walletDID, err)
			}
			// TODO: Check whether there's already a presentation for this DID on the service,
			//       and whether it needs to be updated
			if err = c.registerPresentation(ctx, walletDID, walletCredentials, definition); err != nil {
				log.Logger().Warnf("Failed to register presentation on service '%s' for DID '%s': %s", definition.ID, walletDID, err)
			}
		}
	}
}

func (c client) registerPresentation(ctx context.Context, walletDID did.DID, walletCredentials []vc.VerifiableCredential, definition ServiceDefinition) error {
	_, signInstructions, err := definition.PresentationDefinition.PresentationSubmissionBuilder().
		AddWallet(walletDID, walletCredentials).
		Build(vc.JWTPresentationProofFormat)
	if err != nil {
		return err
	}
	if signInstructions.Empty() {
		// Wallet does not have the right credentials for this service
		// TODO: Might want to log this when this DID was considered eligible for registration
		return nil
	}
	// There's 1 wallet in the submission builder, so there's 1 sign instruction
	opts := holder.PresentationOptions{}
	presentation, err := c.wallet.BuildPresentation(ctx, signInstructions[0].VerifiableCredentials, opts, &walletDID, false)
	if err != nil {
		return err
	}
	client := apiClient.New()
	httpResponse, err := client.RegisterPresentation(ctx, definition.ID, *presentation)
	if httpResponse.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code %d", httpResponse.StatusCode)
	}
	return nil
}
