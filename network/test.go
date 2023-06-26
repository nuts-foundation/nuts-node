/*
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

package network

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/sirupsen/logrus"
)

// NewTestNetworkInstance creates a new Transactions instance that writes it data to a test directory.
func NewTestNetworkInstance(t *testing.T) *Network {
	testDirectory := io.TestDirectory(t)
	// speedup tests by disabling file sync
	defaultBBoltOptions.NoSync = true
	config := TestNetworkConfig()
	store := didstore.NewTestStore(t)
	cryptoInstance := crypto.NewMemoryCryptoInstance()
	eventPublisher := events.NewManager()
	ctrl := gomock.NewController(t)
	pkiMock := pki.NewMockValidator(ctrl)
	pkiMock.EXPECT().SetVerifyPeerCertificateFunc(gomock.Any()).AnyTimes()
	newInstance := NewNetworkInstance(
		config,
		didservice.KeyResolver{Store: store},
		cryptoInstance,
		didservice.Resolver{Store: store},
		didservice.Finder{Store: store},
		eventPublisher,
		storage.NewTestStorageEngine(testDirectory).GetProvider(ModuleName),
		pkiMock,
	)
	if err := newInstance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory})); err != nil {
		logrus.Fatal(err)
	}
	return newInstance
}

// TestNetworkConfig creates new network config with a test directory as data path.
func TestNetworkConfig() Config {
	config := DefaultConfig()
	config.GrpcAddr = "localhost:5555"
	config.EnableDiscovery = false
	return config
}
