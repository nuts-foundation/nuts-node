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

package didsubject

import (
	"context"

	"github.com/nuts-foundation/go-did/did"
)

// MethodManager keeps DID method specific state in sync with the DID sql database.
type MethodManager interface {
	// GenerateDocument generates a new DID document for the given subject.
	// This is done by the method manager since the DID might depend on method specific rules.
	GenerateDocument(ctx context.Context, keyFlags DIDKeyFlags) (*DIDDocument, error)
	// GenerateVerificationMethod generates a new VerificationMethod for the given subject.
	// This is done by the method manager since the VM ID might depend on method specific rules.
	// If keyUsage includes management.KeyAgreement, an RSA key is generated, otherwise an EC key.
	GenerateVerificationMethod(ctx context.Context, controller did.DID, keyUsage DIDKeyFlags) (*did.VerificationMethod, error)
	// Commit is called after changes are made to the primary db.
	// On success, the caller will remove/update the DID changelog.
	Commit(ctx context.Context, event DIDChangeLog) error
	// IsCommitted checks if the event is already committed for the specific method.
	// A mismatch can occur if the method commits before the db is updated (db failure).
	// If a change is not committed, a rollback of the primary db will occur (delete of that version)
	IsCommitted(ctx context.Context, event DIDChangeLog) (bool, error)
}
