/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package store

import (
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-network/pkg/model"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func TestMemory_Write(t *testing.T) {
	store := NewMemoryStore()
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID: *did1,
	}
	meta := types.DocumentMetadata{}

	err := store.Write(doc, meta)

	t.Run("returns no error on successful write", func(t *testing.T) {
		assert.NoError(t, err)
	})

	t.Run("returns error when already exist", func(t *testing.T) {
		err := store.Write(doc, meta)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, types.ErrDIDAlreadyExists, err)
	})
}

func TestMemory_Resolve(t *testing.T) {
	store := NewMemoryStore()
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID: *did1,
	}
	meta := types.DocumentMetadata{}

	_ = store.Write(doc, meta)

	t.Run("returns ErrNotFound on unknown did", func(t *testing.T) {
		did2, _ := did.ParseDID("did:nuts:2")
		_, _, err := store.Resolve(*did2, nil)
		assert.Equal(t, types.ErrNotFound, err)
	})

	t.Run("returns document when found", func(t *testing.T) {
		d, m, err := store.Resolve(*did1, nil)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, d)
		assert.NotNil(t, m)
	})
}

func TestMemory_Update(t *testing.T) {
	store := memory{map[string]memoryEntry{}}
	did1, _ := did.ParseDID("did:nuts:1")
	doc := did.Document{
		ID: *did1,
		Controller: []did.DID{*did1},
	}
	h, _ := model.ParseHash("0000000000000000000000000000000000000000")
	meta := types.DocumentMetadata{
		Hash: h,
	}

	_ = store.Write(doc, meta)

	t.Run("returns no error on success", func(t *testing.T) {
		err := store.Update(*did1, h, doc, meta)
		assert.NoError(t, err)
	})

	t.Run("returns error when hashes don't match", func(t *testing.T) {
		h, _ := model.ParseHash("0000000000000000000000000000000000000001")
		err := store.Update(*did1, h, doc, meta)
		assert.Equal(t, types.ErrUpdateOnOutdatedData, err)
	})

	t.Run("returns error when DID Document is deactivated", func(t *testing.T) {
		did1, _ := did.ParseDID("did:nuts:2")
		store.store[did1.String()] = memoryEntry{
			document: did.Document{ID: *did1},
			metadata: meta,
		}
		err := store.Update(*did1, h, doc, meta)
		assert.Equal(t, types.ErrDeactivated, err)
	})
}
