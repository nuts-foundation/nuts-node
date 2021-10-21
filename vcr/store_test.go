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
	"encoding/json"
	"os"
	"testing"
	"time"

	did2 "github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

func TestVcr_StoreCredential(t *testing.T) {
	// load VC
	target := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &target)
	did, _ := did2.ParseDIDURL(target.Issuer.String())

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
		ctx.docResolver.EXPECT().Resolve(*did, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, nil)

		err := ctx.vcr.StoreCredential(target)

		assert.NoError(t, err)
	})

	t.Run("error - validation", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.vcr.StoreCredential(vc.VerifiableCredential{})

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
