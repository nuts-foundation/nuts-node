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
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
)

// ConceptFinder can resolve VC backed concepts for a DID.
// Deprecated: remove after V2
type ConceptFinder interface {
	// Get returns the requested concept as concept.Concept for the subject or ErrNotFound
	// It also returns untrusted credentials when allowUntrusted == true
	Get(conceptName string, allowUntrusted bool, subject string) (concept.Concept, error)

	// SearchConcept returns matching concepts based upon a query. It returns an empty list if no matches have been found.
	// It also returns untrusted credentials when allowUntrusted == true
	// a context must be passed to prevent long-running queries
	SearchConcept(ctx context.Context, conceptName string, allowUntrusted bool, query map[string]string) ([]concept.Concept, error)
}

// Finder is the VCR interface for searching VCs
type Finder interface {
	// SearchLegacy for matching VCs based upon a query. It returns an empty list if no matches have been found.
	// It also returns untrusted credentials when allowUntrusted == true
	// a context must be passed to prevent long-running queries
	// Deprecated: remove after V2
	SearchLegacy(ctx context.Context, query concept.Query, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error)

	Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error)

	ExpandAndConvert(credential vc.VerifiableCredential) ([]SearchTerm, error)
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
	// It can handle duplicates.
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

// VCR is the interface that covers all functionality of the vcr store.
type VCR interface {
	Issuer() issuer.Issuer
	Holder() holder.Holder
	Verifier() verifier.Verifier

	// Issue creates and publishes a new VC.
	// An optional expirationDate can be given.
	// VCs are stored when the network has successfully published them.
	Issue(vcToIssue vc.VerifiableCredential) (*vc.VerifiableCredential, error)
	// Revoke a credential based on its ID, the Issuer will be resolved automatically.
	// The statusDate will be set to the current time.
	// It returns an error if the credential, issuer or private key can not be found.
	Revoke(ID ssi.URI) (*credential.Revocation, error)

	Finder
	ConceptFinder
	Resolver
	TrustManager
	Validator
	Writer
}
