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

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
)

// Finder is the VCR interface for searching VCs
type Finder interface {
	// Search for matching VCs based upon a query. It returns an empty list if no matches have been found.
	// It also returns untrusted credentials when allowUntrusted == true
	// a context must be passed to prevent long-running queries
	Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error)
}

// Writer is the interface that groups al the VC write methods
type Writer interface {
	// StoreCredential writes a VC to storage. Before writing, it calls Verify!
	// It can handle duplicates.
	StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error
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

	Finder
	Resolver
	TrustManager
	Writer
}
