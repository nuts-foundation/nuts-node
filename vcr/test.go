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
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// keyID matches the keys in /test
const testKID = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#sNGDQ3NlOe6Icv0E7_ufviOLG6Y25bSEyS5EbXBgp8Y"

// NewTestVCRInstance returns a new vcr instance to be used for integration tests. Any data is stored in the
// specified test directory.
func NewTestVCRInstance(t *testing.T) *vcr {
	// speedup tests
	noSync = true
	testDirectory := io.TestDirectory(t)
	// give network a sub directory to avoid duplicate networks in tests
	newInstance := NewVCRInstance(
		nil,
		nil,
		nil,
		network.NewTestNetworkInstance(path.Join(testDirectory, "network")),
	).(*vcr)

	if err := newInstance.Configure(core.ServerConfig{Datadir: testDirectory}); err != nil {
		t.Fatal(err)
	}
	if err := newInstance.Start(); err != nil {
		t.Fatal(err)
	}

	return newInstance
}

type mockContext struct {
	ctrl            *gomock.Controller
	crypto          *crypto.MockKeyStore
	tx              *network.MockTransactions
	vcr             *vcr
	keyResolver     *types.MockKeyResolver
	docResolver     *types.MockDocResolver
	serviceResolver *doc.MockServiceResolver
}

func newMockContext(t *testing.T) mockContext {
	// speedup tests
	noSync = true

	testDir := io.TestDirectory(t)
	ctrl := gomock.NewController(t)
	crypto := crypto.NewMockKeyStore(ctrl)
	tx := network.NewMockTransactions(ctrl)
	tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).AnyTimes()
	keyResolver := types.NewMockKeyResolver(ctrl)
	docResolver := types.NewMockDocResolver(ctrl)
	serviceResolver := doc.NewMockServiceResolver(ctrl)
	vcr := NewVCRInstance(crypto, docResolver, keyResolver, tx).(*vcr)
	vcr.serviceResolver = serviceResolver
	vcr.trustConfig = trust.NewConfig(path.Join(testDir, "trust.yaml"))

	if err := vcr.Configure(core.ServerConfig{Datadir: testDir}); err != nil {
		t.Fatal(err)
	}
	if err := vcr.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vcr.Shutdown()
	})
	return mockContext{
		ctrl:            ctrl,
		crypto:          crypto,
		tx:              tx,
		vcr:             vcr,
		keyResolver:     keyResolver,
		docResolver:     docResolver,
		serviceResolver: serviceResolver,
	}
}
