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

package didweb

import (
	"strings"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_NewDocument(t *testing.T) {
	rootDID := did.MustParseDID("did:example:123")
	keyStore := nutsCrypto.NewMemoryCryptoInstance()
	ctx := audit.TestContext()
	db := testDB(t)
	manager := NewManager(rootDID, "iam", keyStore, db)

	t.Run("random id", func(t *testing.T) {
		doc, err := manager.NewDocument(ctx, orm.AssertionKeyUsage())

		require.NoError(t, err)
		assert.NotNil(t, doc)
		assert.True(t, strings.HasPrefix(doc.DID.ID, "did:example:123:iam:"))
		require.Len(t, doc.VerificationMethods, 1)
		assert.True(t, strings.HasPrefix(doc.VerificationMethods[0].ID, "did:example:123:iam:"))
	})
}
