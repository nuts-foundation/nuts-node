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
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/vcr/verifier"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/stretchr/testify/assert"
)

func TestNewAmbassador(t *testing.T) {
	a := NewAmbassador(nil, nil, nil)

	assert.NotNil(t, a)
}

func TestAmbassador_Configure(t *testing.T) {
	t.Run("calls network.subscribe", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nMock := network.NewMockTransactions(ctrl)
		defer ctrl.Finish()

		a := NewAmbassador(nMock, nil, nil)
		nMock.EXPECT().Subscribe(dag.TransactionPayloadAddedEvent, gomock.Any(), gomock.Any()).MinTimes(2)

		a.Configure()
	})
}

func TestAmbassador_vcCallback(t *testing.T) {
	payload := []byte(concept.TestCredential)
	tx, _ := dag.NewTransaction(hash.EmptyHash(), types.VcDocumentType, nil, nil, 0)
	stx := tx.(dag.Transaction)
	validAt := stx.SigningTime()

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := NewMockWriter(ctrl)
		defer ctrl.Finish()

		target := vc.VerifiableCredential{}
		a := NewAmbassador(nil, wMock, nil).(ambassador)
		wMock.EXPECT().StoreCredential(gomock.Any(), &validAt).DoAndReturn(func(f interface{}, g interface{}) error {
			target = f.(vc.VerifiableCredential)
			return nil
		})

		err := a.vcCallback(stx, payload)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY#123", target.ID.String())
	})

	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := NewMockWriter(ctrl)
		defer ctrl.Finish()

		a := NewAmbassador(nil, wMock, nil).(ambassador)
		wMock.EXPECT().StoreCredential(gomock.Any(), &validAt).Return(errors.New("b00m!"))

		err := a.vcCallback(stx, payload)

		assert.Error(t, err)
	})

	t.Run("error - invalid payload", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := NewMockWriter(ctrl)
		defer ctrl.Finish()

		a := NewAmbassador(nil, wMock, nil).(ambassador)

		err := a.vcCallback(stx, []byte("{"))

		assert.Error(t, err)
	})
}

func Test_ambassador_jsonLDRevocationCallback(t *testing.T) {
	payload, _ := os.ReadFile("test/ld-revocation.json")
	tx, _ := dag.NewTransaction(hash.EmptyHash(), types.RevocationLDDocumentType, nil, nil, 0)
	stx := tx.(dag.Transaction)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		revocation := credential.Revocation{}
		assert.NoError(t, json.Unmarshal(payload, &revocation))

		mockVerifier := verifier.NewMockVerifier(ctrl)
		mockVerifier.EXPECT().RegisterRevocation(revocation)
		a := NewAmbassador(nil, nil, mockVerifier).(ambassador)

		err := a.jsonLDRevocationCallback(stx, payload)
		assert.NoError(t, err)
	})

	t.Run("error - invalid payload", func(t *testing.T) {
		a := NewAmbassador(nil, nil, nil).(ambassador)

		err := a.jsonLDRevocationCallback(stx, []byte("b00m"))
		assert.EqualError(t, err, "revocation processing failed: invalid character 'b' looking for beginning of value")
	})

	t.Run("error - storing fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockVerifier := verifier.NewMockVerifier(ctrl)
		mockVerifier.EXPECT().RegisterRevocation(gomock.Any()).Return(errors.New("foo"))
		a := NewAmbassador(nil, nil, mockVerifier).(ambassador)

		err := a.jsonLDRevocationCallback(stx, payload)
		assert.EqualError(t, err, "foo")
	})
}
