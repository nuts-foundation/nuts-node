/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package vcr

import (
	"context"
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/presentation"
	"github.com/nuts-foundation/nuts-node/vcr/proof"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	_ "github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// ErrInvalidIssuer is returned when a credential is issued by a DID that is unknown or when the private key is missing.
var ErrInvalidIssuer = errors.New("invalid credential issuer")

// ErrInvalidSubject is returned when a credential is issued to a DID that is unknown or revoked.
var ErrInvalidSubject = errors.New("invalid credential subject")

// ErrNotFound is returned when a credential can not be found based on its ID.
var ErrNotFound = errors.New("credential not found")

// ErrRevoked is returned when a credential has been revoked and the required action requires it to not be revoked.
var ErrRevoked = errors.New("credential is revoked")

// ErrUntrusted is returned when a credential is resolved or searched but its issuer is not trusted.
var ErrUntrusted = errors.New("credential issuer is untrusted")

// ErrInvalidCredential is returned when validation failed
var ErrInvalidCredential = errors.New("invalid credential")

// ErrInvalidPeriod is returned when the credential is not valid at the given time.
var ErrInvalidPeriod = errors.New("credential not valid at given time")

var vcDocumentType = "application/vc+json"

var revocationDocumentType = "application/vc+json;type=revocation"

// ConceptFinder can resolve VC backed concepts for a DID.
type ConceptFinder interface {
	// Get returns the requested concept as concept.Concept for the subject or ErrNotFound
	// It also returns untrusted credentials when allowUntrusted == true
	Get(conceptName string, allowUntrusted bool, subject string) (concept.Concept, error)

	// Search for matching concepts based upon a query. It returns an empty list if no matches have been found.
	// It also returns untrusted credentials when allowUntrusted == true
	// a context must be passed to prevent long-running queries
	Search(ctx context.Context, conceptName string, allowUntrusted bool, query map[string]string) ([]concept.Concept, error)
}

// Validator is the VCR interface for validation options
type Validator interface {
	// Validate checks if the given credential:
	// - is not revoked
	// - is valid at the given time (or now if not give)
	// - has a valid issuer
	// - has a valid signature if checkSignature is true
	// if allowUntrusted == false, the issuer must also be a trusted DID
	// May return ErrRevoked, ErrUntrusted or ErrInvalidPeriod
	Validate(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error
}

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
}

// TrustManager bundles all trust related methods in one interface
type TrustManager interface {
	// Trust adds trust for a Issuer/CredentialType combination.
	Trust(credentialType ssi.URI, issuer ssi.URI) error
	// Untrust removes trust for a Issuer/CredentialType combination.
	Untrust(credentialType ssi.URI, issuer ssi.URI) error
	// Trusted returns a list of trusted issuers for given credentialType
	Trusted(credentialType ssi.URI) ([]ssi.URI, error)
	// Untrusted returns a list of untrusted issuers based on known credentials
	Untrusted(credentialType ssi.URI) ([]ssi.URI, error)
}

// Resolver binds all read type of operations into an interface
type Resolver interface {
	// Registry returns the concept registry as read-only
	Registry() concept.Reader
	// Resolve returns a credential based on its ID.
	// The optional resolveTime will resolve the credential at that point in time.
	// The credential will still be returned in the case of ErrRevoked and ErrUntrusted.
	// For other errors, nil is returned
	Resolve(ID ssi.URI, resolveTime *time.Time) (*vc.VerifiableCredential, error)
}

type Presenter interface {
	BuildVerifiablePresentation(credentials []vc.VerifiableCredential, proofOptions proof.ProofOptions, did did.DID, validateVC bool) (*presentation.VerifiablePresentation, error)
}

type Verifier interface {
	VerifyPresentation(verifiablePresentation presentation.VerifiablePresentation) error
}

type PresentationManager interface {
}

// VCR is the interface that covers all functionality of the vcr store.
type VCR interface {
	// Issue creates and publishes a new VC.
	// An optional expirationDate can be given.
	// VCs are stored when the network has successfully published them.
	Issue(vcToIssue vc.VerifiableCredential) (*vc.VerifiableCredential, error)
	// Revoke a credential based on its ID, the Issuer will be resolved automatically.
	// The statusDate will be set to the current time.
	// It returns an error if the credential, issuer or private key can not be found.
	Revoke(ID ssi.URI) (*credential.Revocation, error)

	ConceptFinder
	Resolver
	TrustManager
	Validator
	Writer
	PresentationManager
	Verifier
	Presenter
}
