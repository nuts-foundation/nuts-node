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
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

func TestVcr_StoreCredential(t *testing.T) {
	// load VC
	target := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &target)

	// load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()
		timeFunc = func() time.Time {
			return now
		}
		defer func() {
			timeFunc = time.Now
		}()

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), nil).Return(pk, nil)

		err := ctx.vcr.StoreCredential(target, nil)

		assert.NoError(t, err)
	})

	t.Run("ok - with validAt", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), &now).Return(pk, nil)

		err := ctx.vcr.StoreCredential(target, &now)

		assert.NoError(t, err)
	})

	t.Run("ok - already exists", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), &now).Return(pk, nil)

		_ = ctx.vcr.StoreCredential(target, &now)

		err := ctx.vcr.StoreCredential(target, &now)

		assert.NoError(t, err)
	})

	t.Run("error - already exists, but differs", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), &now).Return(pk, nil)

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

func TestVcr_StoreRevocation(t *testing.T) {
	// load VC
	r := credential.Revocation{}
	rJSON, _ := os.ReadFile("test/revocation.json")
	json.Unmarshal(rJSON, &r)

	// load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), gomock.Any()).Return(pk, nil)

		err := ctx.vcr.StoreRevocation(r)

		assert.NoError(t, err)
	})

	t.Run("error - validation", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.vcr.StoreRevocation(credential.Revocation{})

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

		if !assert.NoError(t, err) {
			return
		}
		doc, err := ctx.vcr.credentialCollection().Get(ref[:])
		assert.NoError(t, err)
		assert.NotNil(t, doc)
	})
}
