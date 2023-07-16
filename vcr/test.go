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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"go.uber.org/mock/gomock"
	"path"
	"testing"
)

// TestVCRContext contains a VCR and underlying services that can be used to do an integration test.
type TestVCRContext struct {
	DIDStore    didstore.Store
	KeyStore    crypto.KeyStore
	DIDResolver types.DIDResolver
	KeyResolver types.KeyResolver
	VCR         VCR
}

func NewTestVCRContext(t *testing.T, keyStore crypto.KeyStore) TestVCRContext {
	didStore := didstore.NewTestStore(t)
	didResolver := didservice.NutsDIDResolver{Store: didStore}
	ctx := TestVCRContext{
		DIDStore:    didStore,
		KeyStore:    keyStore,
		DIDResolver: didResolver,
		KeyResolver: didservice.KeyResolver{Resolver: didResolver},
	}

	testDirectory := io.TestDirectory(t)
	// give network a subdirectory to avoid duplicate networks in tests
	newInstance := NewVCRInstance(
		ctx.KeyStore,
		ctx.DIDStore,
		network.NewTestNetworkInstance(t),
		jsonld.NewTestJSONLDManager(t),
		events.NewTestManager(t),
		storage.NewTestStorageEngine(t),
		pki.New(), nil,
	).(*vcr)

	if err := newInstance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory})); err != nil {
		t.Fatal(err)
	}
	if err := newInstance.Start(); err != nil {
		t.Fatal(err)
	}
	ctx.VCR = newInstance

	return ctx
}

// NewTestVCRInstance returns a new vcr instance to be used for integration tests. Any data is stored in the
// specified test directory.
func NewTestVCRInstance(t *testing.T) *vcr {
	testDirectory := io.TestDirectory(t)
	// give network a subdirectory to avoid duplicate networks in tests
	newInstance := NewVCRInstance(
		nil,
		nil,
		network.NewTestNetworkInstance(t),
		jsonld.NewTestJSONLDManager(t),
		events.NewTestManager(t),
		storage.NewTestStorageEngine(t),
		pki.New(), nil,
	).(*vcr)

	if err := newInstance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory})); err != nil {
		t.Fatal(err)
	}
	if err := newInstance.Start(); err != nil {
		t.Fatal(err)
	}

	return newInstance
}

func NewTestVCRInstanceInDir(t *testing.T, testDirectory string) *vcr {
	storageEngine := storage.New()
	_ = storageEngine.Configure(core.TestServerConfig(core.ServerConfig{Datadir: path.Join(testDirectory, "data")}))
	// give network a subdirectory to avoid duplicate networks in tests
	newInstance := NewVCRInstance(
		nil,
		nil,
		network.NewTestNetworkInstance(t),
		jsonld.NewTestJSONLDManager(t),
		events.NewTestManager(t),
		storageEngine,
		pki.New(), nil,
	).(*vcr)

	if err := newInstance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory})); err != nil {
		t.Fatal(err)
	}
	if err := newInstance.Start(); err != nil {
		t.Fatal(err)
	}

	return newInstance
}

type mockContext struct {
	ctrl            *gomock.Controller
	tx              *network.MockTransactions
	vcr             *vcr
	keyResolver     *types.MockKeyResolver
	didResolver     *types.MockDIDResolver
	serviceResolver *types.MockServiceResolver
	crypto          *crypto.Crypto
}

func newMockContext(t *testing.T) mockContext {
	testDir := io.TestDirectory(t)
	ctrl := gomock.NewController(t)
	tx := network.NewMockTransactions(ctrl)
	tx.EXPECT().WithPersistency().AnyTimes()
	tx.EXPECT().Subscribe("vcr_vcs", gomock.Any(), gomock.Any())
	tx.EXPECT().Subscribe("vcr_revocations", gomock.Any(), gomock.Any())
	tx.EXPECT().CleanupSubscriberEvents("vcr_vcs", gomock.Any())
	keyResolver := types.NewMockKeyResolver(ctrl)
	didResolver := types.NewMockDIDResolver(ctrl)
	serviceResolver := types.NewMockServiceResolver(ctrl)
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	eventManager := events.NewTestManager(t)
	storageClient := storage.NewTestStorageEngine(t)
	cryptoInstance := crypto.NewMemoryCryptoInstance()
	vcr := NewVCRInstance(cryptoInstance, didResolver, tx, jsonldManager, eventManager, storageClient, pki.New(), nil).(*vcr)
	vcr.serviceResolver = serviceResolver
	vcr.keyResolver = keyResolver
	vcr.didResolver = didResolver
	vcr.pkiProvider = pki.New()
	vcr.trustConfig = trust.NewConfig(path.Join(testDir, "trust.yaml"))
	if err := vcr.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDir})); err != nil {
		t.Fatal(err)
	}
	if err := vcr.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := vcr.Shutdown(); err != nil {
			t.Fatal(err)
		}
	})
	return mockContext{
		ctrl:            ctrl,
		crypto:          cryptoInstance,
		tx:              tx,
		vcr:             vcr,
		keyResolver:     keyResolver,
		didResolver:     didResolver,
		serviceResolver: serviceResolver,
	}
}
