/*
 *  Nuts node
 *  Copyright (C) 2021 Nuts community
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package types

import (
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestCopy(t *testing.T) {
	timeBefore := time.Now().Add(time.Hour * -24)
	timeNow := time.Now()
	timeLater := time.Now().Add(time.Hour * +24)
	h, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")

	meta := DocumentMetadata{
		Created:            timeBefore,
		Updated:            &timeNow,
		Hash:               h,
		Deactivated:        false,
		SourceTransactions: []hash.SHA256Hash{h},
	}
	numFields := 6

	t.Run("returns error if metadata can be manipulated", func(t *testing.T) {
		var metaCopy DocumentMetadata

		// Copy
		metaCopy = meta.Copy()
		assert.True(t, reflect.DeepEqual(meta, metaCopy))

		// Updated
		metaCopy = meta.Copy()
		*metaCopy.Updated = timeLater
		assert.False(t, reflect.DeepEqual(meta, metaCopy))

		// Hash
		metaCopy.Hash[0] = 0
		assert.NotEqual(t, metaCopy.Hash, meta.Hash, "Hash is not deep-copied")

		// SourceTransactions
		metaCopy.SourceTransactions[0] = hash.SHA256Hash{20}
		assert.NotEqual(t, metaCopy.SourceTransactions, meta.SourceTransactions, "SourceTransactions is not deep-copied")

		// if this test fails, please make sure the Copy() method is updated as well!
		assert.Equal(t, numFields, reflect.TypeOf(DocumentMetadata{}).NumField())
	})
}

func TestDocumentMetadata_IsConflicted(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		assert.True(t, DocumentMetadata{SourceTransactions: []hash.SHA256Hash{hash.EmptyHash(), hash.EmptyHash()}}.IsConflicted())
	})

	t.Run("false", func(t *testing.T) {
		assert.False(t, DocumentMetadata{}.IsConflicted())
	})
}

func Test_deactivatedError_Is(t *testing.T) {
	assert.ErrorIs(t, ErrDeactivated, ErrDeactivated)
	assert.ErrorIs(t, ErrNoActiveController, ErrDeactivated)
	assert.NotErrorIs(t, io.EOF, ErrDeactivated)
}
