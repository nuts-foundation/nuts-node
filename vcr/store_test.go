/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package vcr

import (
	"crypto/ecdsa"
	"crypto/sha1"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestVcr_StoreCredential(t *testing.T) {
	// load VC
	target := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &target)

	// load pub key
	pke := spi.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.didResolver.EXPECT().Resolve(gomock.Any(), &types.ResolveMetadata{}).Return(documentWithPublicKey(t, pk), nil, nil)

		err := ctx.vcr.StoreCredential(target, nil)

		assert.NoError(t, err)
	})

	t.Run("ok - with validAt", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()

		ctx.didResolver.EXPECT().Resolve(gomock.Any(), &types.ResolveMetadata{ResolveTime: &now}).Return(documentWithPublicKey(t, pk), nil, nil)

		err := ctx.vcr.StoreCredential(target, &now)

		assert.NoError(t, err)
	})

	t.Run("ok - already exists", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()

		ctx.didResolver.EXPECT().Resolve(gomock.Any(), &types.ResolveMetadata{ResolveTime: &now}).Return(documentWithPublicKey(t, pk), nil, nil)

		_ = ctx.vcr.StoreCredential(target, &now)

		err := ctx.vcr.StoreCredential(target, &now)

		assert.NoError(t, err)
	})

	t.Run("error - already exists, but differs", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()

		ctx.didResolver.EXPECT().Resolve(gomock.Any(), &types.ResolveMetadata{ResolveTime: &now}).Return(documentWithPublicKey(t, pk), nil, nil)

		_ = ctx.vcr.StoreCredential(target, &now)

		target.CredentialSubject = []interface{}{
			map[string]interface{}{
				"name": "John Doe",
				"age":  "42",
			},
		}
		err := ctx.vcr.StoreCredential(target, &now)

		assert.Error(t, err)
		assert.ErrorContains(t, err, "credential with same ID but different content already exists")
		assert.ErrorContains(t, err, target.ID.String())
	})

	t.Run("error - validation", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.vcr.StoreCredential(vc.VerifiableCredential{}, nil)

		assert.Error(t, err)
	})
}

func TestStore_writeCredential(t *testing.T) {
	// load VC
	target := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &target)

	t.Run("ok - stored in JSON-LD collection", func(t *testing.T) {
		ctx := newMockContext(t)
		vcBytes, _ := json.Marshal(target)
		ref := sha1.Sum(vcBytes)

		err := ctx.vcr.writeCredential(target)

		require.NoError(t, err)
		doc, err := ctx.vcr.credentialCollection().Get(ref[:])
		assert.NoError(t, err)
		assert.NotNil(t, doc)
	})

	t.Run("ok - accepts credentials without custom type", func(t *testing.T) {
		ctx := newMockContext(t)
		vc := vc.VerifiableCredential{}
		vcBytes, _ := json.Marshal(vc)
		ref := sha1.Sum(vcBytes)

		err := ctx.vcr.writeCredential(vc)

		require.NoError(t, err)
		doc, err := ctx.vcr.credentialCollection().Get(ref[:])
		assert.NoError(t, err)
		assert.NotNil(t, doc)
	})
}
