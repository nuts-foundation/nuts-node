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
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	vcr "github.com/nuts-foundation/nuts-node/vcr/types"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

// NewIssuer creates a new issuer which implements the Issuer interface.
func NewIssuer(store Store, publisher Publisher, docResolver vdr.DocResolver, keyStore crypto.KeyStore, jsonldManager jsonld.JSONLD, trustConfig *trust.Config) Issuer {
	resolver := vdrKeyResolver{docResolver: docResolver, keyResolver: keyStore}
	return &issuer{
		store:         store,
		publisher:     publisher,
		keyResolver:   resolver,
		keyStore:      keyStore,
		jsonldManager: jsonldManager,
		trustConfig:   trustConfig,
	}
}

type issuer struct {
	store         Store
	publisher     Publisher
	keyResolver   keyResolver
	keyStore      crypto.KeyStore
	trustConfig   *trust.Config
	jsonldManager jsonld.JSONLD
}

// Issue creates a new credential, signs, stores it.
// If publish is true, it publishes the credential to the network using the configured Publisher
// Use the public flag to pass the visibility settings to the Publisher.
func (i issuer) Issue(ctx context.Context, credentialOptions vc.VerifiableCredential, publish, public bool) (*vc.VerifiableCredential, error) {
	createdVC, err := i.buildVC(ctx, credentialOptions)
	if err != nil {
		return nil, err
	}

	// Sanity check: all provided fields must be defined by the context: otherwise they're not protected by the signature
	err = credential.AllFieldsDefinedValidator{
		DocumentLoader: i.jsonldManager.DocumentLoader(),
	}.Validate(*createdVC)
	if err != nil {
		return nil, err
	}

	// Validate the VC using the type-specific validator
	validator := credential.FindValidator(*createdVC)
	if err := validator.Validate(*createdVC); err != nil {
		return nil, err
	}

	// Trust credential before storing/publishing, otherwise it might self-issued credentials might not be trusted,
	// if AddTrust() fails for whatever reason.
	// Only 1 allowed for now, but looping over all types (VerifiableCredential is excluded by ExtractTypes()) is future-proof.
	for _, credentialType := range credential.ExtractTypes(*createdVC) {
		// MustParseURI is safe since it came from vc.Type, which contains URIs
		if err := i.trustConfig.AddTrust(ssi.MustParseURI(credentialType), createdVC.Issuer); err != nil {
			return nil, fmt.Errorf("failed to trust issuer when issuing VC (did=%s,type=%s): %w", createdVC.Issuer, credentialType, err)
		}
	}

	if err = i.store.StoreCredential(*createdVC); err != nil {
		return nil, fmt.Errorf("unable to store the issued credential: %w", err)
	}

	if publish {
		publisher := oidc4vciPublisher{}
		if err := publisher.PublishCredential(ctx, *createdVC, public); err != nil {
			return nil, fmt.Errorf("unable to publish the issued credential: %w", err)
		}
	}
	return createdVC, nil
}

func (i issuer) buildVC(ctx context.Context, credentialOptions vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	if len(credentialOptions.Type) != 1 {
		return nil, core.InvalidInputError("can only issue credential with 1 type")
	}

	issuerDID, err := did.ParseDID(credentialOptions.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}

	key, err := i.keyResolver.ResolveAssertionKey(*issuerDID)
	if err != nil {
		const errString = "failed to sign credential: could not resolve an assertionKey for issuer: %w"
		// Differentiate between a DID document not found and some other error:
		if errors.Is(err, vdr.ErrNotFound) {
			return nil, core.InvalidInputError(errString, err)
		}
		return nil, fmt.Errorf(errString, err)
	}

	credentialID := ssi.MustParseURI(fmt.Sprintf("%s#%s", issuerDID.String(), uuid.New().String()))
	unsignedCredential := vc.VerifiableCredential{
		Context:           credentialOptions.Context,
		ID:                &credentialID,
		Type:              credentialOptions.Type,
		CredentialSubject: credentialOptions.CredentialSubject,
		Issuer:            credentialOptions.Issuer,
		ExpirationDate:    credentialOptions.ExpirationDate,
		IssuanceDate:      time.Now(),
	}
	if !unsignedCredential.ContainsContext(vc.VCContextV1URI()) {
		unsignedCredential.Context = append(unsignedCredential.Context, vc.VCContextV1URI())
	}

	defaultType := vc.VerifiableCredentialTypeV1URI()
	if !unsignedCredential.IsType(defaultType) {
		unsignedCredential.Type = append(unsignedCredential.Type, defaultType)
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

	webSig := signature.JSONWebSignature2020{ContextLoader: i.jsonldManager.DocumentLoader(), Signer: i.keyStore}
	signingResult, err := proof.NewLDProof(proofOptions).Sign(ctx, credentialAsMap, webSig, key)
	if err != nil {
		return nil, err
	}

	b, _ = json.Marshal(signingResult)
	signedCredential := &vc.VerifiableCredential{}
	_ = json.Unmarshal(b, signedCredential)

	return signedCredential, nil
}

func (i issuer) Revoke(ctx context.Context, credentialID ssi.URI) (*credential.Revocation, error) {
	// Previously we first tried to resolve the credential, but that's not necessary:
	// if the credential doesn't actually exist the revocation doesn't apply to anything, no harm done.
	// Although it is a bit ugly, it helps issuers to revoke credentials that they don't have anymore,
	// for whatever reason (e.g. incorrect database backup/restore).
	isRevoked, err := i.isRevoked(credentialID)
	if err != nil {
		return nil, fmt.Errorf("error while checking revocation status: %w", err)
	}
	if isRevoked {
		return nil, vcr.ErrRevoked
	}

	revocation, err := i.buildRevocation(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	err = i.publisher.PublishRevocation(ctx, *revocation)
	if err != nil {
		return nil, fmt.Errorf("failed to publish revocation: %w", err)
	}

	// Store the revocation after it has been published
	if err := i.store.StoreRevocation(*revocation); err != nil {
		return nil, fmt.Errorf("unable to store revocation: %w", err)
	}

	log.Logger().
		WithField(core.LogFieldCredentialID, credentialID).
		Info("Verifiable Credential revoked")
	return revocation, nil
}

func (i issuer) buildRevocation(ctx context.Context, credentialID ssi.URI) (*credential.Revocation, error) {
	// Sanity check: since we don't check existence of the VC, at least somewhat guard against mistyped credential IDs
	// (although nobody should be typing those in).
	_, err := uuid.Parse(credentialID.Fragment)
	if err != nil {
		return nil, core.InvalidInputError("invalid credential ID")
	}

	// find issuer from credential ID
	issuer := credentialID
	issuer.Path = ""
	issuer.Fragment = ""
	issuerDID, err := did.ParseDID(issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer: %w", err)
	}

	assertionKey, err := i.keyResolver.ResolveAssertionKey(*issuerDID)
	if err != nil {
		const errString = "failed to revoke credential (%s): could not resolve an assertionKey for issuer: %w"
		// Differentiate between a DID document not found and some other error:
		if errors.Is(err, vdr.ErrNotFound) {
			return nil, core.InvalidInputError(errString, credentialID, err)
		}
		return nil, fmt.Errorf(errString, credentialID, err)
	}
	// set defaults
	revocation := credential.BuildRevocation(issuerDID.URI(), credentialID)

	revocationAsMap := map[string]interface{}{}
	b, _ := json.Marshal(revocation)
	_ = json.Unmarshal(b, &revocationAsMap)

	ldProof := proof.NewLDProof(proof.ProofOptions{Created: time.Now()})
	webSig := signature.JSONWebSignature2020{ContextLoader: i.jsonldManager.DocumentLoader(), Signer: i.keyStore}
	signingResult, err := ldProof.Sign(ctx, revocationAsMap, webSig, assertionKey)
	if err != nil {
		return nil, err
	}

	signingResultAsMap := signingResult.(proof.SignedDocument)
	b, _ = json.Marshal(signingResultAsMap)
	signedRevocation := credential.Revocation{}
	_ = json.Unmarshal(b, &signedRevocation)

	return &signedRevocation, nil
}

func (i issuer) isRevoked(credentialID ssi.URI) (bool, error) {
	_, err := i.store.GetRevocation(credentialID)
	switch err {
	case nil: // revocation found
		return true, nil
	case vcr.ErrMultipleFound:
		return true, nil
	case vcr.ErrNotFound:
		return false, nil
	default:
		return true, err
	}
}

func (i issuer) SearchCredential(credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	return i.store.SearchCredential(credentialType, issuer, subject)
}
