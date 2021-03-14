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
	"io/ioutil"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
)

func TestVcr_StoreCredential(t *testing.T) {
	// load VC
	vc := did.VerifiableCredential{}
	vcJSON, _ := ioutil.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &vc)

	// load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := ioutil.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		ctx.vdr.EXPECT().ResolveSigningKey(gomock.Any(), nil).Return(pk, nil)

		err := ctx.vcr.StoreCredential(vc)

		assert.NoError(t, err)
	})

	t.Run("error - validation", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})

		err := ctx.vcr.StoreCredential(did.VerifiableCredential{})

		assert.Error(t, err)
	})
}


func TestVcr_StoreRevocation(t *testing.T) {
	// load VC
	r := credential.Revocation{}
	rJSON, _ := ioutil.ReadFile("test/revocation.json")
	json.Unmarshal(rJSON, &r)

	// load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := ioutil.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		ctx.vdr.EXPECT().ResolveSigningKey(gomock.Any(), gomock.Any()).Return(pk, nil)

		err := ctx.vcr.StoreRevocation(r)

		assert.NoError(t, err)
	})

	t.Run("error - validation", func(t *testing.T) {
		ctx := newMockContext(t)
		defer ctx.ctrl.Finish()

		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})

		err := ctx.vcr.StoreRevocation(credential.Revocation{})

		assert.Error(t, err)
	})
}
