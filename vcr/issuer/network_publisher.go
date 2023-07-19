/*
 * Copyright (C) 2022 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

type networkPublisher struct {
	networkTx       network.Transactions
	didResolver     vdr.DIDResolver
	serviceResolver vdr.ServiceResolver
	keyResolver     keyResolver
}

// NewNetworkPublisher creates a new networkPublisher which implements the Publisher interface.
// It is the default implementation to use for issuers to publish credentials and revocations to the Nuts network.
func NewNetworkPublisher(networkTx network.Transactions, store didstore.Store, keyResolver crypto.KeyResolver) Publisher {
	didResolver := didservice.Resolver{Store: store}
	return &networkPublisher{
		networkTx:       networkTx,
		didResolver:     didResolver,
		serviceResolver: didservice.ServiceResolver{Store: store},
		keyResolver: vdrKeyResolver{
			publicKeyResolver:  didservice.KeyResolver{Store: store},
			privateKeyResolver: keyResolver,
		},
	}

}

func (p networkPublisher) PublishCredential(ctx context.Context, verifiableCredential vc.VerifiableCredential, public bool) error {
	issuerDID, err := did.ParseDIDURL(verifiableCredential.Issuer.String())
	if err != nil {
		return fmt.Errorf("invalid credential issuer: %w", err)
	}

	if len(verifiableCredential.CredentialSubject) == 0 {
		return fmt.Errorf("missing credentialSubject")
	}

	participants := []did.DID{}
	if !public {
		participants, err = p.generateParticipants(verifiableCredential)
		if err != nil {
			return err
		}
	}

	key, err := p.keyResolver.ResolveAssertionKey(ctx, *issuerDID)
	if err != nil {
		return fmt.Errorf("could not resolve an assertion key for issuer: %w", err)
	}

	// find did document/metadata for originating TXs
	_, meta, err := p.didResolver.Resolve(*issuerDID, nil)
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(verifiableCredential)
	tx := network.TransactionTemplate(types.VcDocumentType, payload, key).
		WithTimestamp(verifiableCredential.IssuanceDate).
		WithAdditionalPrevs(meta.SourceTransactions).
		WithPrivate(participants)

	_, err = p.networkTx.CreateTransaction(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to publish credential, error while creating transaction: %w", err)
	}
	log.Logger().
		WithField(core.LogFieldCredentialID, verifiableCredential.ID).
		WithField(core.LogFieldCredentialType, verifiableCredential.Type).
		Info("Verifiable Credential published")

	return nil
}

func (p networkPublisher) generateParticipants(verifiableCredential vc.VerifiableCredential) ([]did.DID, error) {
	issuer, _ := did.ParseDID(verifiableCredential.Issuer.String())
	participants := make([]did.DID, 0)
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
			return nil, fmt.Errorf("failed to resolve participating node (did=%s): %w", vcp.String(), err)
		}

		participants = append(participants, *serviceOwner)
	}
	return participants, nil
}

func (p networkPublisher) resolveNutsCommServiceOwner(DID did.DID) (*did.DID, error) {
	serviceUser := didservice.MakeServiceReference(DID, transport.NutsCommServiceType)

	service, err := p.serviceResolver.Resolve(serviceUser, 5)
	if err != nil {
		return nil, fmt.Errorf("could not resolve NutsComm service owner: %w", err)
	}
	var nutsCommEndpoint transport.NutsCommURL
	if err := service.UnmarshalServiceEndpoint(&nutsCommEndpoint); err != nil {
		return nil, fmt.Errorf("could not resolve NutsComm service owner: %w", err)
	}
	serviceID := service.ID
	serviceID.Fragment = ""
	serviceID.Path = ""

	// impossible that this will return an error, so we won't wrap it within a different message
	return did.ParseDID(serviceID.String())
}

func (p networkPublisher) PublishRevocation(ctx context.Context, revocation credential.Revocation) error {
	issuerDID, err := did.ParseDIDURL(revocation.Issuer.String())
	if err != nil {
		return fmt.Errorf("invalid revocation issuer: %w", err)
	}
	key, err := p.keyResolver.ResolveAssertionKey(ctx, *issuerDID)
	if err != nil {
		return fmt.Errorf("could not resolve an assertion key for issuer: %w", err)
	}

	// find did document/metadata for originating TXs
	_, meta, err := p.didResolver.Resolve(*issuerDID, nil)
	if err != nil {
		return fmt.Errorf("could not resolve issuer DID document: %w", err)
	}
	payload, _ := json.Marshal(revocation)

	tx := network.TransactionTemplate(types.RevocationLDDocumentType, payload, key).
		WithAdditionalPrevs(meta.SourceTransactions).
		WithTimestamp(revocation.Date)

	_, err = p.networkTx.CreateTransaction(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to publish revocation, error while creating transaction: %w", err)
	}
	return nil
}
