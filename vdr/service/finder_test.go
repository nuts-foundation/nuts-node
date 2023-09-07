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
 */

package service

import (
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func TestIsActive(t *testing.T) {
	p := IsActive()

	t.Run("active", func(t *testing.T) {
		assert.True(t, p.Match(did.Document{}, types.DocumentMetadata{Deactivated: false}))
	})

	t.Run("deactivated", func(t *testing.T) {
		assert.False(t, p.Match(did.Document{}, types.DocumentMetadata{Deactivated: true}))
	})
}

func TestValidAt(t *testing.T) {
	now := time.Now()
	later := now.AddDate(0, 0, 1)
	meta := types.DocumentMetadata{
		Created: now.AddDate(0, 0, -1),
		Updated: &later,
	}

	t.Run("ok - latest", func(t *testing.T) {
		p := ValidAt(now)
		assert.True(t, p.Match(did.Document{}, types.DocumentMetadata{Created: now.AddDate(0, 0, -1), Updated: nil}))
	})

	t.Run("ok - updated", func(t *testing.T) {
		p := ValidAt(now.AddDate(0, 0, 2))
		assert.True(t, p.Match(did.Document{}, meta))
	})

	t.Run("not yet", func(t *testing.T) {
		p := ValidAt(now.AddDate(0, 0, -2))
		assert.False(t, p.Match(did.Document{}, meta))
	})

	t.Run("updated", func(t *testing.T) {
		p := ValidAt(now)
		assert.False(t, p.Match(did.Document{}, meta))
	})
}

func TestByServiceType(t *testing.T) {
	ID, _ := did.ParseDID("did:nuts:123")
	p := ByServiceType("NutsComm")

	t.Run("ok", func(t *testing.T) {
		doc := did.Document{ID: *ID, Controller: []did.DID{*ID}, Service: []did.Service{
			{
				Type:            "NutsComm",
				ServiceEndpoint: "grpc://nuts.nl:5555",
			},
		}}

		assert.True(t, p.Match(doc, types.DocumentMetadata{}))
	})

	t.Run("ignore", func(t *testing.T) {
		docIgnore := did.Document{ID: *ID, Controller: []did.DID{*ID}, Service: []did.Service{
			{
				Type:            "NutsComm",
				ServiceEndpoint: "did:nuts:321/serviceEndpoint#1",
			},
		}}

		assert.False(t, p.Match(docIgnore, types.DocumentMetadata{}))
	})
}
