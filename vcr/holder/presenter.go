/*
 * Copyright (C) 2024 Nuts community
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

package holder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/piprate/json-gold/ld"
	"strings"
	"time"
)

type presenter struct {
	documentLoader ld.DocumentLoader
	keyStore       crypto.KeyStore
	keyResolver    resolver.KeyResolver
}

func (p presenter) buildSubmission(ctx context.Context, holderDID did.DID, credentials []vc.VerifiableCredential, presentationDefinition pe.PresentationDefinition,
	acceptedFormats map[string]map[string][]string, params BuildParams) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error) {
	// match against the wallet's credentials
	// if there's a match, create a VP and call the token endpoint
	// If the token endpoint succeeds, return the access token
	// If no presentation definition matches, return a 412 "no matching credentials" error
	builder := presentationDefinition.PresentationSubmissionBuilder()
	builder.AddWallet(holderDID, credentials)

	// Find supported VP format, matching support from:
	// - what the local Nuts node supports
	// - the presentation definition "claimed format designation" (optional)
	// - the verifier's metadata (optional)
	formatCandidates := credential.OpenIDSupportedFormats(oauth.DefaultOpenIDSupportedFormats())
	formatCandidates = formatCandidates.Match(credential.OpenIDSupportedFormats(acceptedFormats))
	if presentationDefinition.Format != nil {
		formatCandidates = formatCandidates.Match(credential.DIFClaimFormats(*presentationDefinition.Format))
	}
	// todo: next to the format selection, also check for algorithm support
	format := pe.ChooseVPFormat(formatCandidates.Map)
	if format == "" {
		return nil, nil, errors.New("requester, verifier (authorization server metadata) and presentation definition don't share a supported VP format")
	}
	presentationSubmission, signInstructions, err := builder.Build(format)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build presentation submission: %w", err)
	}
	if signInstructions.Empty() {
		// we'll allow empty if no credentials are required
		if presentationDefinition.CredentialsRequired() {
			return nil, nil, ErrNoCredentials
		}
		// add empty sign instruction
		signInstructions = append(signInstructions, pe.SignInstruction{Holder: holderDID})
		presentationSubmission = pe.PresentationSubmission{
			Id:            uuid.NewString(),
			DefinitionId:  presentationDefinition.Id,
			DescriptorMap: make([]pe.InputDescriptorMappingObject, 0),
		}
	}

	// todo: support multiple wallets
	vp, err := p.buildPresentation(ctx, &holderDID, signInstructions[0].VerifiableCredentials, PresentationOptions{
		Format: format,
		ProofOptions: proof.ProofOptions{
			Created:   time.Now(),
			Challenge: &params.Nonce,
			Domain:    &params.Audience,
			Expires:   &params.Expires,
			Nonce:     &params.Nonce,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verifiable presentation: %w", err)
	}
	return vp, &presentationSubmission, nil
}

func (p presenter) buildPresentation(ctx context.Context, signerDID *did.DID, credentials []vc.VerifiableCredential, options PresentationOptions) (*vc.VerifiablePresentation, error) {
	var err error
	if signerDID == nil {
		signerDID, err = credential.ResolveSubjectDID(credentials...)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve signer DID from VCs for creating VP: %w", err)
		}
	}

	kid, _, err := p.keyResolver.ResolveKey(*signerDID, nil, resolver.NutsSigningKeyType)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve assertion key for signing VP (did=%s): %w", *signerDID, err)
	}

	switch options.Format {
	case JWTPresentationFormat:
		return p.buildJWTPresentation(ctx, *signerDID, credentials, options, kid.String())
	case "":
		fallthrough
	case JSONLDPresentationFormat:
		return p.buildJSONLDPresentation(ctx, *signerDID, credentials, options, kid.String())
	default:
		return nil, fmt.Errorf("unsupported presentation proof format: %s", options.Format)
	}
}

// buildJWTPresentation builds a JWT presentation according to https://www.w3.org/TR/vc-data-model/#json-web-token
func (p presenter) buildJWTPresentation(ctx context.Context, subjectDID did.DID, credentials []vc.VerifiableCredential, options PresentationOptions, keyID string) (*vc.VerifiablePresentation, error) {
	headers := map[string]interface{}{
		jws.TypeKey: "JWT",
	}
	id := did.DIDURL{DID: subjectDID}
	id.Fragment = strings.ToLower(uuid.NewString())
	claims := map[string]interface{}{
		jwt.SubjectKey: subjectDID.String(),
		jwt.JwtIDKey:   id.String(),
		"vp": vc.VerifiablePresentation{
			Context:              append([]ssi.URI{VerifiableCredentialLDContextV1}, options.AdditionalContexts...),
			Type:                 append([]ssi.URI{VerifiablePresentationLDType}, options.AdditionalTypes...),
			VerifiableCredential: credentials,
		},
	}
	if options.ProofOptions.Nonce != nil {
		claims["nonce"] = *options.ProofOptions.Nonce
	}
	if options.ProofOptions.Domain != nil {
		claims[jwt.AudienceKey] = *options.ProofOptions.Domain
	}
	if options.ProofOptions.Created.IsZero() {
		claims[jwt.NotBeforeKey] = time.Now().Unix()
	} else {
		claims[jwt.NotBeforeKey] = int(options.ProofOptions.Created.Unix())
	}
	if options.ProofOptions.Expires != nil {
		claims[jwt.ExpirationKey] = int(options.ProofOptions.Expires.Unix())
	}
	for claimName, value := range options.ProofOptions.AdditionalProperties {
		claims[claimName] = value
	}
	token, err := p.keyStore.SignJWT(ctx, claims, headers, keyID)
	if err != nil {
		return nil, fmt.Errorf("unable to sign JWT presentation: %w", err)
	}
	return vc.ParseVerifiablePresentation(token)
}

func (p presenter) buildJSONLDPresentation(ctx context.Context, subjectDID did.DID, credentials []vc.VerifiableCredential, options PresentationOptions, keyID string) (*vc.VerifiablePresentation, error) {
	ldContext := []ssi.URI{VerifiableCredentialLDContextV1, signature.JSONWebSignature2020Context}
	ldContext = append(ldContext, options.AdditionalContexts...)
	types := []ssi.URI{VerifiablePresentationLDType}
	types = append(types, options.AdditionalTypes...)

	id := did.DIDURL{DID: subjectDID}
	id.Fragment = strings.ToLower(uuid.NewString())
	idURI := id.URI()
	unsignedVP := &vc.VerifiablePresentation{
		ID:                   &idURI,
		Context:              ldContext,
		Type:                 types,
		VerifiableCredential: credentials,
	}

	// Convert to map[string]interface{} for signing
	documentBytes, err := unsignedVP.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var document proof.Document
	err = json.Unmarshal(documentBytes, &document)
	if err != nil {
		return nil, err
	}

	ldProof := proof.NewLDProof(options.ProofOptions)
	signingResult, err := ldProof.
		Sign(ctx, document, signature.JSONWebSignature2020{ContextLoader: p.documentLoader, Signer: p.keyStore}, keyID)
	if err != nil {
		return nil, fmt.Errorf("unable to sign VP with LD proof: %w", err)
	}
	resultJSON, _ := json.Marshal(signingResult)
	return vc.ParseVerifiablePresentation(string(resultJSON))
}
