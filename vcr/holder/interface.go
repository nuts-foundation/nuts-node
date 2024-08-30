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

package holder

import (
	"context"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
)

// VerifiableCredentialLDContextV1 holds the URI of the JSON-LD context for Verifiable Credentials.
var VerifiableCredentialLDContextV1 = ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")

// VerifiablePresentationLDType holds the JSON-LD type for Verifiable Presentations.
var VerifiablePresentationLDType = ssi.MustParseURI("VerifiablePresentation")

const (
	JSONLDPresentationFormat = vc.JSONLDPresentationProofFormat
	JWTPresentationFormat    = vc.JWTPresentationProofFormat
)

// Wallet holds Verifiable Credentials and can present them.
type Wallet interface {
	core.Diagnosable

	// BuildPresentation builds and signs a Verifiable Presentation using the given Verifiable Credentials.
	// The assertion key used for signing it is taken from signerDID's DID document.
	// If signerDID is not provided, it will be derived from the credentials credentialSubject.id fields. But only if all provided credentials have the same (singular) credentialSubject.id field.
	BuildPresentation(ctx context.Context, credentials []vc.VerifiableCredential, options PresentationOptions, signerDID *did.DID, validateVC bool) (*vc.VerifiablePresentation, error)

	// BuildSubmission builds a Verifiable Presentation based on the given presentation definition.
	// additionalCredentials can be given to have the submission consider extra credentials that are not in the wallet.
	BuildSubmission(ctx context.Context, walletDIDs []did.DID, additionalCredentials map[did.DID][]vc.VerifiableCredential, presentationDefinition pe.PresentationDefinition, acceptedFormats map[string]map[string][]string, params BuildParams) (*vc.VerifiablePresentation, *pe.PresentationSubmission, error)

	// List returns all credentials in the wallet for the given holder.
	// If the wallet does not contain any credentials for the given holder, it returns an empty list.
	List(ctx context.Context, holderDID did.DID) ([]vc.VerifiableCredential, error)

	// Remove removes the given credential from the wallet.
	// If the credential is not in the wallet, it returns ErrNotFound.
	Remove(ctx context.Context, holderDID did.DID, credentialID ssi.URI) error

	// Put adds the given credentials to the wallet. It is an all-or-nothing operation:
	// if one of them fails, none of the credentials are added.
	Put(ctx context.Context, credentials ...vc.VerifiableCredential) error

	// IsEmpty returns true if the wallet contains no credentials at all (for all holder DIDs).
	IsEmpty() (bool, error)
}

// PresentationOptions contains parameters used to create the right VerifiablePresentation
// It's up to the caller to make sure the AdditionalTypes are covered by the AdditionalContexts
type PresentationOptions struct {
	// AdditionalContexts contains the contexts to be added in addition to https://www.w3.org/2018/credentials/v1 and the context for JSONWebSignature2020
	AdditionalContexts []ssi.URI
	// AdditionalTypes contains the VerifiablePresentation types in addition to VerifiablePresentation
	AdditionalTypes []ssi.URI
	// Holder specifies the holder property.
	Holder *ssi.URI
	// ProofOptions contains the options for a specific proof.
	ProofOptions proof.ProofOptions
	// Format contains the requested format for the VerifiablePresentation. If not set, it defaults to JSON-LD.
	// Valid options are: ldp_vp or jwt_vp
	Format string
}
