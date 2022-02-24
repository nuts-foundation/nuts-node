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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/piprate/json-gold/ld"
	"time"
)

// NewIssuer creates a new issuer which implements the Issuer interface.
func NewIssuer(store Store, publisher Publisher, docResolver vdr.DocResolver, keyStore crypto.KeyStore, contextLoader ld.DocumentLoader) Issuer {
	resolver := vdrKeyResolver{docResolver: docResolver, keyResolver: keyStore}
	return &issuer{
		store:         store,
		publisher:     publisher,
		keyResolver:   resolver,
		contextLoader: contextLoader,
	}
}

type issuer struct {
	store         Store
	publisher     Publisher
	keyResolver   keyResolver
	contextLoader ld.DocumentLoader
}

// Issue creates a new credential, signs, stores it.
// If publish is true, it publishes the credential to the network using the configured Publisher
// Use the public flag to pass the visibility settings to the Publisher.
func (i issuer) Issue(credentialOptions vc.VerifiableCredential, publish, public bool) (*vc.VerifiableCredential, error) {
	createdVC, err := i.buildVC(credentialOptions)
	if err != nil {
		return nil, err
	}

	validator, _ := credential.FindValidatorAndBuilder(*createdVC)
	if err := validator.Validate(*createdVC); err != nil {
		return nil, err
	}

	if err = i.store.StoreCredential(*createdVC); err != nil {
		return nil, fmt.Errorf("unable to store the issued credential: %w", err)
	}

	if publish {
		if err := i.publisher.PublishCredential(*createdVC, public); err != nil {
			return nil, fmt.Errorf("unable to publish the issued credential: %w", err)
		}
	}
	return createdVC, nil
}

func (i issuer) buildVC(credentialOptions vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	if len(credentialOptions.Type) != 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}

	// find issuer
	issuer, err := did.ParseDID(credentialOptions.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}

	credentialID, _ := ssi.ParseURI(fmt.Sprintf("%s#%s", issuer.String(), uuid.New().String()))
	unsignedCredential := vc.VerifiableCredential{
		Context:           append(credentialOptions.Context, vc.VCContextV1URI()),
		ID:                credentialID,
		Type:              credentialOptions.Type,
		CredentialSubject: credentialOptions.CredentialSubject,
		Issuer:            credentialOptions.Issuer,
		ExpirationDate:    credentialOptions.ExpirationDate,
		IssuanceDate:      time.Now(),
	}

	defaultType := vc.VerifiableCredentialTypeV1URI()
	if !unsignedCredential.IsType(defaultType) {
		unsignedCredential.Type = append(unsignedCredential.Type, defaultType)
	}

	key, err := i.keyResolver.ResolveAssertionKey(*issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential, could not resolve an assertionKey for issuer: %w", err)
	}

	credentialAsMap := map[string]interface{}{}
	b, _ := json.Marshal(unsignedCredential)
	_ = json.Unmarshal(b, &credentialAsMap)

	// Set created date to the issuanceDate if set
	created := time.Now()
	if !credentialOptions.IssuanceDate.IsZero() {
		created = credentialOptions.IssuanceDate
	}
	proofOptions := proof.ProofOptions{Created: created}

	// This is the code for signing with the new LDProofs. Enable when we release V1, otherwise current nodes cannot
	// validate new transactions.
	//signingResult, err := proof.NewLDProof(proofOptions).
	//	Sign(credentialAsMap, signature.JSONWebSignature2020{ContextLoader: i.contextLoader}, key)

	signingResult, err := proof.NewLegacyLDProof(proofOptions).Sign(credentialAsMap, signature.LegacyNutsSuite{}, key)
	if err != nil {
		return nil, err
	}

	b, _ = json.Marshal(signingResult)
	signedCredential := &vc.VerifiableCredential{}
	_ = json.Unmarshal(b, signedCredential)

	return signedCredential, nil
}

func (i issuer) Revoke(credentialID ssi.URI) error {
	//TODO implement me
	panic("implement me")
}

func (i issuer) CredentialResolver() CredentialSearcher {
	return i.store
}

func (i issuer) SearchCredential(context ssi.URI, credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	return i.store.SearchCredential(context, credentialType, issuer, subject)
}
