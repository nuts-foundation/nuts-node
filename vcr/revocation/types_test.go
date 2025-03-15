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

package revocation

import (
	"context"
	"crypto"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
)

// newTestStatusList2021 returns a StatusList2021 that does not Sign or VerifySignature, with a SQLite db containing the dids, and no http-client.
func newTestStatusList2021(t testing.TB, dids ...did.DID) *StatusList2021 {
	cs := NewStatusList2021(storage.NewTestStorageEngine(t).GetSQLDatabase(), nil, "https://example.com")
	cs.Sign = noopSign
	cs.ResolveKey = noopResolveKey
	cs.VerifySignature = noopSignVerify
	storage.AddDIDtoSQLDB(t, cs.db, dids...)
	return cs
}

func noopSign(_ context.Context, unsignedCredential vc.VerifiableCredential, _ string) (*vc.VerifiableCredential, error) {
	// marshal-unmarshal credential to set the .raw field
	bs, err := json.Marshal(unsignedCredential)
	if err != nil {
		return nil, err
	}
	return &unsignedCredential, json.Unmarshal(bs, &unsignedCredential)
}

func noopSignVerify(_ vc.VerifiableCredential, _ *time.Time) error { return nil }

// noopResolveKey should only be used in tests where CredentialStatus.Sign ignores the key (noopSign)
func noopResolveKey(_ did.DID, _ *time.Time, _ resolver.RelationType) (string, crypto.PublicKey, error) {
	return "", nil, nil
}

func TestEntry_Validate(t *testing.T) {
	makeValidCSEntry := func() StatusList2021Entry {
		return StatusList2021Entry{
			ID:                   "https://example-com/credentials/status/3#94567",
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      "94567",
			StatusListCredential: "https://example-com/credentials/status/3",
		}
	}

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, makeValidCSEntry().Validate())
	})
	t.Run("error - id == statusListCredential", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.ID = entry.StatusListCredential
		err := entry.Validate()
		assert.EqualError(t, err, "StatusList2021Entry.id is the same as the StatusList2021Entry.statusListCredential")
	})
	t.Run("error - incorrect type", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.Type = "Wrong Type"
		err := entry.Validate()
		assert.EqualError(t, err, "StatusList2021Entry.type must be StatusList2021Entry")
	})
	t.Run("error - missing statusPurpose", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusPurpose = ""
		err := entry.Validate()
		assert.EqualError(t, err, "StatusList2021Entry.statusPurpose is required")
	})
	t.Run("error - statusListIndex is negative", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusListIndex = "-1"
		err := entry.Validate()
		assert.EqualError(t, err, "invalid StatusList2021Entry.statusListIndex")
	})
	t.Run("error - statusListIndex is not a number", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusListIndex = "one"
		err := entry.Validate()
		assert.EqualError(t, err, "invalid StatusList2021Entry.statusListIndex")
	})
	t.Run("error - statusListCredential is not a valid URL", func(t *testing.T) {
		entry := makeValidCSEntry()
		entry.StatusListCredential = "not a URL"
		err := entry.Validate()
		assert.EqualError(t, err, "parse StatusList2021Entry.statusListCredential URL: parse \"not a URL\": invalid URI for request")
	})
}
