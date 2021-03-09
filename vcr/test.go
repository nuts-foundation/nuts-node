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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/sirupsen/logrus"
)

// keyID matches the keys in /test
const kid = "did:nuts:EgFjg8zqN6eN3oiKtSvmUucao4VF18m2Q9fftAeANTBd#twlH6rB8ArZrknmBRWLXhao3FutZtvOm0hnNhcruenI"

// NewTestVCRInstance returns a new vcr instance to be used for integration tests. Any data is stored in the
// specified test directory.
func NewTestVCRInstance(testDirectory string) *vcr {
	newInstance := NewVCRInstance(
		nil,
		nil,
		network.NewTestNetworkInstance(testDirectory),
	).(*vcr)

	if err := newInstance.Configure(core.ServerConfig{Datadir: testDirectory}); err != nil {
		logrus.Fatal(err)
	}
	return newInstance
}

type mockContext struct {
	ctrl   *gomock.Controller
	crypto *crypto.MockKeyStore
	tx     *network.MockTransactions
	vcr    *vcr
	vdr    *types.MockResolver
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	crypto := crypto.NewMockKeyStore(ctrl)
	tx := network.NewMockTransactions(ctrl)
	vdr := types.NewMockResolver(ctrl)

	return mockContext{
		ctrl:   ctrl,
		crypto: crypto,
		tx:     tx,
		vcr:    NewVCRInstance(crypto, vdr, tx).(*vcr),
		vdr:    vdr,
	}
}
