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

package orm

import (
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
)

func TestDIDEventLog_DID(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		id := did.MustParseDID("did:example:123")
		didEventLog := DIDChangeLog{
			DIDDocumentVersion: DIDDocument{
				DID: DID{ID: id.String()},
			},
		}

		assert.Equal(t, id, didEventLog.DID())
	})
	t.Run("malformed DID", func(t *testing.T) {
		didEventLog := DIDChangeLog{
			DIDDocumentVersion: DIDDocument{
				DID: DID{ID: "malformed"},
			},
		}

		assert.Equal(t, did.DID{}, didEventLog.DID())
	})
}

func TestDIDEventLog_Method(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		id := did.MustParseDID("did:example:123")
		didEventLog := DIDChangeLog{
			DIDDocumentVersion: DIDDocument{
				DID: DID{ID: id.String()},
			},
		}

		assert.Equal(t, "example", didEventLog.Method())
	})
	t.Run("malformed DID", func(t *testing.T) {
		didEventLog := DIDChangeLog{
			DIDDocumentVersion: DIDDocument{
				DID: DID{ID: "malformed"},
			},
		}

		assert.Equal(t, "_unknown", didEventLog.Method())
	})
}
