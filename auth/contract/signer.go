/*
 * Nuts node
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
 */

package contract

// Signer is responsible for signing contract signing requests. Signing is done by making use of asynchronous SigningSessions.
type Signer interface {
	// SigningSessionStatus returns the current status of the signing session or services.ErrSessionNotFound if not found
	// todo: name should have been SessionStatus, but its currently in use by the old interface
	SigningSessionStatus(sessionID string) (SigningSessionResult, error)
	// StartSession starts a session for the implementing signer
	// todo: name should have been StartSession, but its currently in use by the old interface
	StartSigningSession(rawContractText string) (SessionPointer, error)
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
	VerifiablePresentation() (VerifiablePresentation, error)
}
