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
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	did "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/stretchr/testify/assert"
)

func TestNewAmbassador(t *testing.T) {
	a := NewAmbassador(nil, nil)

	assert.NotNil(t, a)
}

func TestAmbassador_Configure(t *testing.T) {
	t.Run("calls network.subscribe", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		nMock := network.NewMockTransactions(ctrl)
		defer ctrl.Finish()

		a := NewAmbassador(nMock, nil)
		nMock.EXPECT().Subscribe(gomock.Any(), gomock.Any()).MinTimes(2)

		a.Configure()
	})
}

func TestAmbassador_vcCallback(t *testing.T) {
	payload := []byte(concept.TestCredential)
	tx, _ := dag.NewTransaction(hash.EmptyHash(), vcDocumentType, nil)
	stx := tx.(dag.SubscriberTransaction)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := NewMockWriter(ctrl)
		defer ctrl.Finish()

		vc := did.VerifiableCredential{}
		a := NewAmbassador(nil, wMock).(*ambassador)
		wMock.EXPECT().StoreCredential(gomock.Any()).DoAndReturn(func(f interface{}) error {
			vc = f.(did.VerifiableCredential)
			return nil
		})

		err := a.vcCallback(stx, payload)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "did:nuts:1#123", vc.ID.String())
	})

	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wMock := NewMockWriter(ctrl)
		defer ctrl.Finish()

		a := NewAmbassador(nil, wMock).(*ambassador)
		wMock.EXPECT().StoreCredential(gomock.Any()).Return(errors.New("b00m!"))

		err := a.vcCallback(stx, payload)

		assert.Error(t, err)
	})
}
