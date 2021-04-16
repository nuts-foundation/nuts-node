/*
 * Copyright (C) 2021. Nuts community
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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/sirupsen/logrus"
)

// NewTestNetworkInstance creates a new Transactions instance that writes it data to a test directory.
func NewTestNetworkInstance(testDirectory string) *Network {
	config := TestNetworkConfig()
	vdrStore := store.NewMemoryStore()
	newInstance := NewNetworkInstance(config, crypto.NewTestCryptoInstance(testDirectory), doc.KeyResolver{Store: vdrStore})
	if err := newInstance.Configure(core.ServerConfig{Datadir: testDirectory}); err != nil {
		logrus.Fatal(err)
	}
	return newInstance
}

// TestNetworkConfig creates new network config with a test directory as data path.
func TestNetworkConfig() Config {
	config := DefaultConfig()
	config.GrpcAddr = ":5555"
	config.EnableTLS = false
	return config
}
