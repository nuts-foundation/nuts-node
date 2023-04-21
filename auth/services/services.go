/*
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

package services

import (
	"context"
	"github.com/nuts-foundation/go-did/vc"
	"net/http"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/contract"
)

// SignedToken defines the uniform interface to crypto specific implementations such as Irma or x509 tokens.
type SignedToken interface {
	// SignerAttributes extracts a map of attribute names and their values from the signature
	SignerAttributes() (map[string]string, error)
	// Contract extracts the Contract from the SignedToken
	Contract() contract.Contract
}

// VPProofValueParser provides a uniform interface for Authentication services like IRMA or x509 signed tokens
type VPProofValueParser interface {
	// Parse accepts a raw ProofValue from the VP as a string. The parser tries to parse the value into a SignedToken.
	Parse(rawAuthToken string) (SignedToken, error)

	// Verify accepts a SignedToken and verifies the signature using the crypto for the specific implementation of this interface.
	Verify(token SignedToken) error
}

// ContractNotary defines the functions for creating, validating verifiable credentials and draw up a contract.
type ContractNotary interface {
	contract.VPVerifier

	// DrawUpContract draws up a contract from a template and returns a Contract which than can be signed by the user.
	DrawUpContract(ctx context.Context, template contract.Template, orgID did.DID, validFrom time.Time, validDuration time.Duration, organizationCredential *vc.VerifiableCredential) (*contract.Contract, error)

	// CreateSigningSession creates a signing session for the requested contract and means
	CreateSigningSession(sessionRequest CreateSessionRequest) (contract.SessionPointer, error)

	// SigningSessionStatus returns the status of the current signing session or ErrSessionNotFound is sessionID is unknown
	// context is used to pass audit context when using crypto library
	SigningSessionStatus(ctx context.Context, sessionID string) (contract.SigningSessionResult, error)

	Configure() error

	// HandlerFunc returns the Irma server handler func
	HandlerFunc() http.HandlerFunc

	// Start any validator that needs to periodically update its database. Cancel the context to stop these processes.
	Start(ctx context.Context)
}
