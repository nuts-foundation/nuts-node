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

package verifier

import (
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"io"
	"time"
)

// Verifier defines the interface for verifying verifiable credentials.
type Verifier interface {
	// Verify checks credential on full correctness. It checks:
	// validity of the signature
	// if it has been revoked
	// if the issuer is registered as trusted
	Verify(credential vc.VerifiableCredential, allowUntrusted bool, checkSignature bool, validAt *time.Time) error
	// Validate checks the verifiable credential technical correctness
	Validate(credentialToVerify vc.VerifiableCredential, at *time.Time) error
	// IsRevoked checks if the credential is revoked
	IsRevoked(credentialID ssi.URI) (bool, error)
	// RegisterRevocation stores the revocation in the store
	// before storing the revocation gets validated
	RegisterRevocation(revocation credential.Revocation) error

	// VerifyVP verifies the given Verifiable Presentation. If successful, it returns the credentials within the presentation.
	// If verifyVCs is true, it will also verify the credentials inside the VP, checking their correctness, signature and trust status.
	VerifyVP(presentation vc.VerifiablePresentation, verifyVCs bool, validAt *time.Time) ([]vc.VerifiableCredential, error)
}

// ErrNotFound is returned when a credential or revocation can not be found based on its ID.
var ErrNotFound = errors.New("not found")

// VerificationError is used to describe a VC/VP verification failure.
type VerificationError struct {
	msg  string
	args []interface{}
}

// Is checks whether the given error is a VerificationError as well.
func (e VerificationError) Is(other error) bool {
	_, is := other.(VerificationError)
	return is
}

func newVerificationError(msg string, args ...interface{}) error {
	return VerificationError{msg: msg, args: args}
}

func toVerificationError(cause error) error {
	return VerificationError{msg: cause.Error()}
}

func (e VerificationError) Error() string {
	return fmt.Errorf("verification error: "+e.msg, e.args...).Error()
}

// Store defines the interface for a store for a verifier.
// The store is filled with public information such as revoked credentials,
// as well as local defined trust relations between issuer and credential type.
type Store interface {
	// GetRevocation find the revocation by the credential ID
	// Returns an ErrNotFound when the revocation is not in the store
	GetRevocation(id ssi.URI) (*credential.Revocation, error)
	// StoreRevocation writes a revocation to storage.
	StoreRevocation(r credential.Revocation) error
	// Closer closes and frees the underlying resources the store uses.
	io.Closer
}
