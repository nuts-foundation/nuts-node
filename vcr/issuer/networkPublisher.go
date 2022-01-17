package issuer

import (
	"encoding/json"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

type networkPublisher struct {
	networkTx       network.Transactions
	didDocResolver  vdr.DocResolver
	serviceResolver doc.ServiceResolver
	keyResolver     vdrKeyResolver
}

const VcDocumentType = "application/vc+json"

func NewNetworkPublisher(networkTx network.Transactions, docResolver vdr.DocResolver, keyResolver crypto.KeyResolver) Publisher {
	return &networkPublisher{
		networkTx:       networkTx,
		didDocResolver:  docResolver,
		serviceResolver: doc.NewServiceResolver(docResolver),
		keyResolver: vdrKeyResolver{
			docResolver: docResolver,
			keyResolver: keyResolver,
		},
	}

}

func (p networkPublisher) PublishCredential(verifiableCredential vc.VerifiableCredential, public bool) error {
	// create participants list
	participants, err := p.generateParticipants(verifiableCredential, public)
	if err != nil {
		return err
	}
	issuerDID, _ := did.ParseDIDURL(verifiableCredential.Issuer.String())

	key, err := p.keyResolver.ResolveAssertionKey(*issuerDID)

	// find did document/metadata for originating TXs
	_, meta, err := p.didDocResolver.Resolve(*issuerDID, nil)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("could not resolve kid: %w", err)
	}

	payload, _ := json.Marshal(verifiableCredential)
	tx := network.TransactionTemplate(VcDocumentType, payload, key).
		WithTimestamp(verifiableCredential.IssuanceDate).
		WithAdditionalPrevs(meta.SourceTransactions).
		WithPrivate(participants)

	_, err = p.networkTx.CreateTransaction(tx)
	if err != nil {
		return fmt.Errorf("failed to publish credential: %w", err)
	}
	log.Logger().Infof("Verifiable Credential published (id=%s,type=%s)", verifiableCredential.ID, verifiableCredential.Type)

	return nil
}

func (p networkPublisher) generateParticipants(verifiableCredential vc.VerifiableCredential, public bool) ([]did.DID, error) {
	issuer, _ := did.ParseDID(verifiableCredential.Issuer.String())
	participants := make([]did.DID, 0)
	if !public {
		var (
			base                []credential.BaseCredentialSubject
			credentialSubjectID *did.DID
		)
		err := verifiableCredential.UnmarshalCredentialSubject(&base)
		if err == nil {
			credentialSubjectID, err = did.ParseDID(base[0].ID) // earlier validation made sure length == 1 and ID is present
		}
		if err != nil {
			return nil, fmt.Errorf("failed to determine credentialSubject.ID: %w", err)
		}

		// participants are not the issuer and the credentialSubject.id but the DID that holds the concrete endpoint for the NutsComm service
		for _, vcp := range []did.DID{*issuer, *credentialSubjectID} {
			serviceOwner, err := p.resolveNutsCommServiceOwner(vcp)
			if err != nil {
				return nil, fmt.Errorf("could not publish private credential: failed to resolve participating node (did=%s): %w", vcp.String(), err)
			}

			participants = append(participants, *serviceOwner)
		}
	}
	return participants, nil
}

func (p networkPublisher) resolveNutsCommServiceOwner(DID did.DID) (*did.DID, error) {
	serviceUser, _ := ssi.ParseURI(fmt.Sprintf("%s/serviceEndpoint?type=%s", DID.String(), transport.NutsCommServiceType))

	service, err := p.serviceResolver.Resolve(*serviceUser, 5)
	if err != nil {
		return nil, fmt.Errorf("could not resolve NutsComm service owner: %w", err)
	}
	serviceID := service.ID
	serviceID.Fragment = ""
	serviceID.Path = ""

	// impossible that this will return an error, so we won't wrap it within a different message
	return did.ParseDID(serviceID.String())
}

func (p networkPublisher) PublishRevocation(revocation credential.Revocation) error {
	//TODO implement me
	panic("implement me")
}
