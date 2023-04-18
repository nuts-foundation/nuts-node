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
 */

package contract

import (
	"context"
	"github.com/nuts-foundation/go-did/vc"
)

// Signer is responsible for signing contract signing requests. Signing is done by making use of asynchronous SigningSessions.
type Signer interface {
	// SigningSessionStatus returns the current status of the signing session or services.ErrSessionNotFound if not found
	SigningSessionStatus(ctx context.Context, sessionID string) (SigningSessionResult, error)
	// StartSigningSession starts a session for the implementing signer
	// params are signer specific
	StartSigningSession(contract Contract, params map[string]interface{}) (SessionPointer, error)
}

// SessionPointer contains session information for the means how to sign the payload
type SessionPointer interface {
	SessionID() string
	Payload() []byte
	MarshalJSON() ([]byte, error)
}

// SigningSessionResult holds information in the current status of the SigningSession
type SigningSessionResult interface {
	// Status returns the current state of the SigningSession
	Status() string
	// VerifiablePresentation returns a VerifiablePresentation holding the presentation proof and disclosed attributes or an error if
	// no proof is present yet
	VerifiablePresentation() (*vc.VerifiablePresentation, error)
}
