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
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
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
	"github.com/nuts-foundation/nuts-node/vcr/types"
)

// TimeFunc is a function that returns the time used, for e.g. signing time. It can be set for testing purposes.
var TimeFunc = time.Now

// NewIssuer creates a new issuer which implements the Issuer interface.
// If openidIssuerFn is nil, it won't try to issue over OpenID4VCI.
// It needs types.Writer since issued credentials need to be in the general VCR store,
// since that normally happens through receiving the just-issued credential over the network,
// but that doesn't happen when issuing over OpenID4VCI. Thus, it needs to explicitly save it to the VCR store when issuing over OpenID4VCI.
// See https://github.com/nuts-foundation/nuts-node/issues/2063
func NewIssuer(store Store, vcrStore types.Writer, networkPublisher Publisher,
	openidHandlerFn func(ctx context.Context, id did.DID) (OpenIDHandler, error),
	didResolver resolver.DIDResolver, keyStore crypto.KeyStore, jsonldManager jsonld.JSONLD, trustConfig *trust.Config,
) Issuer {
	keyResolver := vdrKeyResolver{
		publicKeyResolver:  resolver.DIDKeyResolver{Resolver: didResolver},
		privateKeyResolver: keyStore,
	}
	return &issuer{
		store:            store,
		networkPublisher: networkPublisher,
		openidHandlerFn:  openidHandlerFn,
		walletResolver: openid4vci.DIDIdentifierResolver{
			ServiceResolver: resolver.DIDServiceResolver{Resolver: didResolver},
		},
		keyResolver:   keyResolver,
		keyStore:      keyStore,
		jsonldManager: jsonldManager,
		trustConfig:   trustConfig,
		vcrStore:      vcrStore,
	}
}

type issuer struct {
	store            Store
	networkPublisher Publisher
	openidHandlerFn  func(ctx context.Context, id did.DID) (OpenIDHandler, error)
	serviceResolver  resolver.ServiceResolver
	keyResolver      keyResolver
	keyStore         crypto.KeyStore
	trustConfig      *trust.Config
	jsonldManager    jsonld.JSONLD
	vcrStore         types.Writer
	walletResolver   openid4vci.IdentifierResolver
}

// Issue creates a new credential, signs, stores it.
// If publish is true, it publishes the credential to the network using the configured Publisher
// Use the public flag to pass the visibility settings to the Publisher.
func (i issuer) Issue(ctx context.Context, template vc.VerifiableCredential, options CredentialOptions) (*vc.VerifiableCredential, error) {
	// Until further notice we don't support publishing JWT VCs, since they're not officially supported by Nuts yet.
	if options.Publish && options.Format == JWTCredentialFormat {
		return nil, errors.New("publishing VC JWTs is not supported")
	}

	createdVC, err := i.buildVC(ctx, template, options)
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

	if options.Publish {
		// Try to issue over OpenID4VCI if it's enabled and if the credential is not public
		// (public credentials are always published on the network).
		if i.openidHandlerFn != nil && !options.Public {
			success, err := i.issueUsingOpenID4VCI(ctx, *createdVC)
			if err != nil {
				// An error occurred, but it's not because the wallet/issuer doesn't support OpenID4VCI.
				log.Logger().
					WithField(core.LogFieldCredentialID, createdVC.ID.String()).
					WithError(err).
					Warnf("Couldn't publish credential over OpenID4VCI, fallback to publish over Nuts network")
			} else if success {
				log.Logger().
					WithField(core.LogFieldCredentialID, createdVC.ID.String()).
					Info("Published credential over OpenID4VCI")
				return createdVC, nil
			} else {
				log.Logger().
					WithField(core.LogFieldCredentialID, createdVC.ID.String()).
					Info("Wallet or issuer does not support OpenID4VCI, fallback to publish over Nuts network")
			}
		}
		if err := i.networkPublisher.PublishCredential(ctx, *createdVC, options.Public); err != nil {
			return nil, fmt.Errorf("unable to publish the issued credential: %w", err)
		}
	}
	return createdVC, nil
}

// issueUsingOpenID4VCI tries to issue the credential over OpenID4VCI. It returns whether the credential was offered successfully.
// If no error is returned and bool is false, it means the wallet does not support OpenID4VCI.
func (i issuer) issueUsingOpenID4VCI(ctx context.Context, credential vc.VerifiableCredential) (bool, error) {
	subjectID, err := credential.SubjectDID()
	if err != nil {
		return false, err
	}
	walletIdentifier, err := i.walletResolver.Resolve(*subjectID)
	if err != nil {
		return false, fmt.Errorf("unable to discover wallet identifier: %w", err)
	}
	if walletIdentifier == "" {
		// Wallet not configured for OpenID4VCI
		return false, nil
	}
	issuerDID, _ := did.ParseDID(credential.Issuer.String()) // can't fail, already created
	openidIssuer, err := i.openidHandlerFn(ctx, *issuerDID)
	if err != nil {
		return false, fmt.Errorf("unable to discover issuer identifier: %w", err)
	}
	err = openidIssuer.OfferCredential(ctx, credential, walletIdentifier)
	if err != nil {
		return false, fmt.Errorf("unable to offer the credential over OpenID4VCI to (wallet: %s): %w", walletIdentifier, err)
	}
	return true, i.vcrStore.StoreCredential(credential, nil)
}

func (i issuer) buildVC(ctx context.Context, template vc.VerifiableCredential, options CredentialOptions) (*vc.VerifiableCredential, error) {
	if len(template.Type) != 1 {
		return nil, core.InvalidInputError("can only issue credential with 1 type")
	}

	issuerDID, err := did.ParseDID(template.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}

	key, err := i.keyResolver.ResolveAssertionKey(ctx, *issuerDID)
	if err != nil {
		const errString = "failed to sign credential: could not resolve an assertionKey for issuer: %w"
		// Differentiate between a DID document not found and some other error:
		if resolver.IsFunctionalResolveError(err) {
			return nil, core.InvalidInputError(errString, err)
		}
		return nil, fmt.Errorf(errString, err)
	}

	credentialID := ssi.MustParseURI(fmt.Sprintf("%s#%s", issuerDID.String(), uuid.New().String()))
	unsignedCredential := vc.VerifiableCredential{
		Context:           template.Context,
		ID:                &credentialID,
		Type:              template.Type,
		CredentialSubject: template.CredentialSubject,
		Issuer:            template.Issuer,
		ExpirationDate:    template.ExpirationDate,
		IssuanceDate:      template.IssuanceDate,
	}
	if unsignedCredential.IssuanceDate == nil || unsignedCredential.IssuanceDate.IsZero() {
		issuanceDate := TimeFunc()
		unsignedCredential.IssuanceDate = &issuanceDate
	}
	if !unsignedCredential.ContainsContext(vc.VCContextV1URI()) {
		unsignedCredential.Context = append(unsignedCredential.Context, vc.VCContextV1URI())
	}

	defaultType := vc.VerifiableCredentialTypeV1URI()
	if !unsignedCredential.IsType(defaultType) {
		unsignedCredential.Type = append(unsignedCredential.Type, defaultType)
	}

	switch options.Format {
	case JWTCredentialFormat:
		return vc.CreateJWTVerifiableCredential(ctx, unsignedCredential, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
			return i.keyStore.SignJWT(ctx, claims, headers, key)
		})
	case "":
		fallthrough
	case JSONLDCredentialFormat:
		return i.buildJSONLDCredential(ctx, unsignedCredential, key)
	default:
		return nil, errors.New("unsupported credential proof format")
	}
}

func (i issuer) buildJSONLDCredential(ctx context.Context, unsignedCredential vc.VerifiableCredential, key crypto.Key) (*vc.VerifiableCredential, error) {
	credentialAsMap := map[string]interface{}{}
	b, _ := json.Marshal(unsignedCredential)
	_ = json.Unmarshal(b, &credentialAsMap)

	proofOptions := proof.ProofOptions{Created: *unsignedCredential.IssuanceDate}

	webSig := signature.JSONWebSignature2020{ContextLoader: i.jsonldManager.DocumentLoader(), Signer: i.keyStore}
	signingResult, err := proof.NewLDProof(proofOptions).Sign(ctx, credentialAsMap, webSig, key)
	if err != nil {
		return nil, err
	}
	credentialJSON, _ := json.Marshal(signingResult)
	return vc.ParseVerifiableCredential(string(credentialJSON))
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
		return nil, types.ErrRevoked
	}

	revocation, err := i.buildRevocation(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	err = i.networkPublisher.PublishRevocation(ctx, *revocation)
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

	assertionKey, err := i.keyResolver.ResolveAssertionKey(ctx, *issuerDID)
	if err != nil {
		const errString = "failed to revoke credential (%s): could not resolve an assertionKey for issuer: %w"
		// Differentiate between a DID document not found and some other error:
		if resolver.IsFunctionalResolveError(err) {
			return nil, core.InvalidInputError(errString, credentialID, err)
		}
		return nil, fmt.Errorf(errString, credentialID, err)
	}
	// set defaults
	revocation := credential.BuildRevocation(issuerDID.URI(), credentialID)

	revocationAsMap := map[string]interface{}{}
	b, _ := json.Marshal(revocation)
	_ = json.Unmarshal(b, &revocationAsMap)

	ldProof := proof.NewLDProof(proof.ProofOptions{Created: TimeFunc()})
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
	case types.ErrMultipleFound:
		return true, nil
	case types.ErrNotFound:
		return false, nil
	default:
		return true, err
	}
}

func (i issuer) SearchCredential(credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	return i.store.SearchCredential(credentialType, issuer, subject)
}
