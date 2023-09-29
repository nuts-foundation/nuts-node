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
	"github.com/nuts-foundation/nuts-node/core"
	"io"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// Publisher publishes new credentials and revocations to a channel. Used by a credential issuer.
type Publisher interface {
	// PublishCredential publishes the credential to the outside world.
	// A public flag is used to indicate if everybody can see the credential, or just the involved parties.
	PublishCredential(ctx context.Context, verifiableCredential vc.VerifiableCredential, public bool) error
	// PublishRevocation publishes the revocation to the outside world.
	// It indicates to the network a credential can no longer be used.
	PublishRevocation(ctx context.Context, revocation credential.Revocation) error
}

type keyResolver interface {
	ResolveAssertionKey(ctx context.Context, issuerDID did.DID) (crypto.Key, error)
}

// Issuer is a role in the network for a party who issues credentials about a subject to a holder.
type Issuer interface {
	// Issue issues a credential by signing an unsigned credential.
	Issue(ctx context.Context, template vc.VerifiableCredential, options CredentialOptions) (*vc.VerifiableCredential, error)
	// Revoke revokes a credential by the provided type.
	// It requires access to the private key of the issuer which will be used to sign the revocation.
	// It returns an error when the credential is not issued by this node or is already revoked.
	// The revocation will be published to the network by the issuers Publisher.
	Revoke(ctx context.Context, credentialID ssi.URI) (*credential.Revocation, error)
	CredentialSearcher
}

// Store defines the interface for an issuer store.
// An implementation stores all the issued credentials and the revocations.
type Store interface {
	core.Diagnosable
	// GetCredential retrieves an issued credential by ID
	// Returns an ErrNotFound when the credential is not in the store
	// Returns an ErrMultipleFound when there are multiple credentials with this ID in the store
	GetCredential(id ssi.URI) (*vc.VerifiableCredential, error)
	// StoreCredential writes a VC to storage.
	StoreCredential(vc vc.VerifiableCredential) error
	// GetRevocation returns a revocation for a credential ID
	// Returns an ErrNotFound when the revocation is not in the store
	// Returns an ErrMultipleFound when there are multiple revocations for this credential ID in the store
	GetRevocation(id ssi.URI) (*credential.Revocation, error)
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
	CredentialSearcher
	// Closer closes and frees the underlying resources the store uses.
	io.Closer
}

// CredentialSearcher defines the functions to resolve or search for credentials.
// It is a separate interface from Store so when an object only needs resolving, it only needs the resolver.
type CredentialSearcher interface {
	// SearchCredential searches for issued credentials
	// If the passed context is empty, it'll not be part of the search query on the DB.
	SearchCredential(credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error)
}

const (
	JSONLDCredentialFormat = vc.JSONLDCredentialProofFormat
	JWTCredentialFormat    = vc.JWTCredentialsProofFormat
)

// CredentialOptions specifies options for issuing a credential.
type CredentialOptions struct {
	// Format specifies the proof format for the issued credential. If not set, it defaults to JSON-LD.
	// Valid options are: ldp_vc or jwt_vc
	Format string
	// Publish param indicates if the credential should be published to the network.
	Publish bool
	// Public param instructs the Publisher to publish the param with a certain visibility.
	Public bool
}
