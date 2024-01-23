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
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"path"
	"testing"
)

// TestVCRContext contains a VCR and underlying services that can be used to do an integration test.
type TestVCRContext struct {
	DIDStore    didstore.Store
	KeyStore    crypto.KeyStore
	KeyResolver resolver.KeyResolver
	VCR         VCR
}

func NewTestVCRContext(t *testing.T, keyStore crypto.KeyStore) TestVCRContext {
	didStore := didstore.NewTestStore(t)
	didResolver := didnuts.Resolver{Store: didStore}
	ctx := TestVCRContext{
		DIDStore:    didStore,
		KeyStore:    keyStore,
		KeyResolver: resolver.DIDKeyResolver{Resolver: didResolver},
	}

	testDirectory := io.TestDirectory(t)
	storageEngine := storage.NewTestStorageEngine(t)
	networkInstance := network.NewTestNetworkInstance(t)
	eventManager := events.NewTestManager(t)
	vdrInstance := vdr.NewVDR(keyStore, networkInstance, didStore, eventManager, storageEngine)
	err := vdrInstance.Configure(core.ServerConfig{URL: "http://nuts.test"})
	require.NoError(t, err)
	newInstance := NewVCRInstance(
		ctx.KeyStore,
		vdrInstance,
		networkInstance,
		jsonld.NewTestJSONLDManager(t),
		eventManager,
		storageEngine,
		pki.New(),
	).(*vcr)

	if err := newInstance.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = testDirectory
	})); err != nil {
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
	didStore := didstore.NewTestStore(t)
	storageEngine := storage.NewTestStorageEngine(t)
	keyStore := crypto.NewMemoryCryptoInstance()
	eventManager := events.NewTestManager(t)
	networkInstance := network.NewNetworkInstance(network.TestNetworkConfig(), didStore, keyStore, eventManager, storageEngine.GetProvider("network"), nil)
	serverCfg := core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = testDirectory
		config.URL = "http://nuts.test"
	})
	_ = networkInstance.Configure(serverCfg)
	vdrInstance := vdr.NewVDR(keyStore, networkInstance, didStore, eventManager, storageEngine)
	err := vdrInstance.Configure(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	newInstance := NewVCRInstance(
		keyStore,
		vdrInstance,
		networkInstance,
		jsonld.NewTestJSONLDManager(t),
		eventManager,
		storageEngine,
		pki.New(),
	).(*vcr)
	if err := newInstance.Configure(serverCfg); err != nil {
		t.Fatal(err)
	}
	if err := newInstance.Start(); err != nil {
		t.Fatal(err)
	}

	return newInstance
}

func NewTestVCRInstanceInDir(t *testing.T, testDirectory string) *vcr {
	didStore := didstore.NewTestStore(t)
	storageEngine := storage.NewTestStorageEngineInDir(nil, testDirectory)
	networkInstance := network.NewTestNetworkInstance(t)
	eventManager := events.NewTestManager(t)
	vdrInstance := vdr.NewVDR(nil, networkInstance, didStore, eventManager, storageEngine)
	err := vdrInstance.Configure(core.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	newInstance := NewVCRInstance(
		nil,
		vdrInstance,
		networkInstance,
		jsonld.NewTestJSONLDManager(t),
		eventManager,
		storageEngine,
		pki.New(),
	).(*vcr)

	if err := newInstance.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = testDirectory
	})); err != nil {
		t.Fatal(err)
	}
	if err := newInstance.Start(); err != nil {
		t.Fatal(err)
	}

	return newInstance
}

type mockContext struct {
	ctrl        *gomock.Controller
	vcr         *vcr
	didResolver *resolver.MockDIDResolver
	crypto      *crypto.Crypto
	vdr         *vdr.MockVDR
}

func newMockContext(t *testing.T) mockContext {
	testDir := io.TestDirectory(t)
	ctrl := gomock.NewController(t)
	tx := network.NewMockTransactions(ctrl)
	tx.EXPECT().WithPersistency().AnyTimes()
	tx.EXPECT().Subscribe("vcr_vcs", gomock.Any(), gomock.Any())
	tx.EXPECT().Subscribe("vcr_revocations", gomock.Any(), gomock.Any())
	tx.EXPECT().CleanupSubscriberEvents("vcr_vcs", gomock.Any())
	didResolver := resolver.NewMockDIDResolver(ctrl)
	vdrInstance := vdr.NewMockVDR(ctrl)
	vdrInstance.EXPECT().Resolver().Return(didResolver).AnyTimes()
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	eventManager := events.NewTestManager(t)
	storageClient := storage.NewTestStorageEngine(t)
	cryptoInstance := crypto.NewMemoryCryptoInstance()
	vcr := NewVCRInstance(cryptoInstance, vdrInstance, tx, jsonldManager, eventManager, storageClient, pki.New()).(*vcr)
	vcr.pkiProvider = pki.New()
	vcr.trustConfig = trust.NewConfig(path.Join(testDir, "trust.yaml"))
	if err := vcr.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = testDir
	})); err != nil {
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
		ctrl:        ctrl,
		crypto:      cryptoInstance,
		vcr:         vcr,
		vdr:         vdrInstance,
		didResolver: didResolver,
	}
}
