/*
 * Copyright (C) 2024 Nuts community
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

package events

import (
	"context"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/sql"

	"github.com/nuts-foundation/go-did/did"
)

type DIDEventType uint8

const (
	DIDEventCreated     = "created"
	DIDEventUpdated     = "updated"
	DIDEventDeactivated = "deactivated"
)

type DIDEvent struct {
	Subject string
	DID     did.DID
	Type    DIDEventType
}

// MethodManager keeps DID method specific state in sync with the DID sql database.
type MethodManager interface {
	// GenerateDocument generates a new DID document for the given subject.
	// This is done by the method manager since the DID might depend on method specific rules.
	// todo replace subject with options?
	GenerateDocument(ctx context.Context, subject string, keyTypes management.DIDKeyFlags) (*did.Document, error)
	// GenerateVerificationMethod generates a new VerificationMethod for the given subject.
	// This is done by the method manager since the VM ID might depend on method specific rules.
	GenerateVerificationMethod(ctx context.Context, controller did.DID) (*did.VerificationMethod, error)
	// OnEvent is called after changes are made to the primary db.
	// On success, it should remove the event from the event log.
	OnEvent(ctx context.Context, event sql.DIDEventLog)
	// Loop starts the DID syncer loop. It should be called in a separate goroutine.
	// It checks if there are any DIDEvents still in the event log.
	Loop(ctx context.Context)
}
