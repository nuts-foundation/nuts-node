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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

// Publisher publishes new credentials and revocations to a channel. Used by a credential issuer.
type Publisher interface {
	PublishCredential(verifiableCredential vc.VerifiableCredential, public bool) error
	PublishRevocation(revocation credential.Revocation) error
}

type keyResolver interface {
	ResolveAssertionKey(issuerDID did.DID) (crypto.Key, error)
}

// Issuer is a role in the network for a party who issues credentials about a subject to a holder.
type Issuer interface {
	Issue(unsignedCredential vc.VerifiableCredential, publish, public bool) (*vc.VerifiableCredential, error)
	Revoke(credentialID ssi.URI) error
	CredentialSearcher
}

// Store defines the interface for an issuer store.
// An implementation stores all the issued credentials and the revocations.
type Store interface {
	// StoreCredential writes a VC to storage.
	StoreCredential(vc vc.VerifiableCredential) error
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
	CredentialSearcher
}

// CredentialSearcher defines the functions to resolve or search for credentials.
// It is a separate interface from Store so when an object only needs resolving, it only needs the resolver.
type CredentialSearcher interface {
	// SearchCredential searches for issued credentials
	SearchCredential(context ssi.URI, credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error)
}
