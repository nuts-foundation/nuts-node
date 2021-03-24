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
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/sirupsen/logrus"
)

// keyID matches the keys in /test
const testKID = "did:nuts:t1DVVAs5fmNba8fdKoTSQNtiGcH49vicrkjZW2KRqpv#h22vbXHX7-lRd1qAJnU63liaehb9sAoBS7RavhvfgR8"

// NewTestVCRInstance returns a new vcr instance to be used for integration tests. Any data is stored in the
// specified test directory.
func NewTestVCRInstance(testDirectory string) *vcr {

	// give network a sub directory to avoid duplicate networks in tests
	newInstance := NewVCRInstance(
		nil,
		nil,
		network.NewTestNetworkInstance(path.Join(testDirectory, "network")),
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
	keyResolver *types.MockKeyResolver
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	crypto := crypto.NewMockKeyStore(ctrl)
	tx := network.NewMockTransactions(ctrl)
	keystore := types.NewMockKeyResolver(ctrl)

	return mockContext{
		ctrl:   ctrl,
		crypto: crypto,
		tx:     tx,
		vcr:    NewVCRInstance(crypto, keystore, tx).(*vcr),
		keyResolver: keystore,
	}
}
