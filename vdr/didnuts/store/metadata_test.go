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

package store

import (
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMetadata_asDocumentMetadata(t *testing.T) {
	someTime, _ := time.Parse(time.RFC3339, time.RFC3339)
	someHash := hash.RandomHash()
	metadata := documentMetadata{
		Created:            someTime,
		Updated:            someTime,
		Hash:               hash.RandomHash(),
		PreviousHash:       &someHash,
		SourceTransactions: []hash.SHA256Hash{hash.RandomHash()},
		Deactivated:        true,
	}

	t.Run("default fields", func(t *testing.T) {
		documentMetadata := metadata.asVDRMetadata()

		assert.Equal(t, metadata.Created, documentMetadata.Created)
		assert.Nil(t, documentMetadata.Updated)
		assert.Equal(t, metadata.Deactivated, documentMetadata.Deactivated)
		assert.Equal(t, metadata.Hash, documentMetadata.Hash)
		assert.Equal(t, metadata.PreviousHash, documentMetadata.PreviousHash)
		assert.Equal(t, metadata.SourceTransactions, documentMetadata.SourceTransactions)
	})

	t.Run("optional updated", func(t *testing.T) {
		cpy := metadata
		otherTime := time.Now()
		cpy.Updated = otherTime

		documentMetadata := cpy.asVDRMetadata()

		require.NotNil(t, documentMetadata.Updated)
		assert.Equal(t, otherTime, *documentMetadata.Updated)
	})
}
