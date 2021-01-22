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

// Package vdr contains a verifiable data registry to the w3c specification
// and provides primitives for storing and working with Nuts DID based identities.
// It provides an easy to work with web api and a command line interface.
// It provides underlying storage back ends to store, update and search for Nuts identities.
package vdr

import (
	"fmt"
	"sync"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/vdr/logging"

	"github.com/nuts-foundation/nuts-network/pkg"

	"github.com/nuts-foundation/nuts-node/vdr/network"

	networkClient "github.com/nuts-foundation/nuts-network/client"
	networkPkg "github.com/nuts-foundation/nuts-network/pkg"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// VDR stands for the Nuts Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the Network, and receives events back from the network which are processed in the store.
// It is also an engine which can be started providing an http API server and client and a
type VDR struct {
	Config            Config
	store             types.Store
	network           networkPkg.NetworkClient
	crypto            crypto.KeyStore
	OnChange          func(registry *Registry)
	networkAmbassador network.Ambassador
	configOnce        sync.Once
	_logger           *logrus.Entry
	closers           []chan struct{}
	didDocCreator     types.DocCreator
}

var instance *VDR
var oneRegistry sync.Once

// ReloadRegistryIdleTimeout defines the cooling down period after receiving a file watcher notification, before
// the registry is reloaded (from disk).
var ReloadRegistryIdleTimeout time.Duration

func init() {
	ReloadRegistryIdleTimeout = 3 * time.Second
}

// RegistryInstance returns the singleton VDR
func RegistryInstance() *VDR {
	if instance != nil {
		return instance
	}
	oneRegistry.Do(func() {
		instance = NewRegistryInstance(DefaultRegistryConfig(), crypto.Instance(), networkClient.NewNetworkClient())
	})

	return instance
}

func NewRegistryInstance(config Config, cryptoClient crypto.KeyStore, networkClient pkg.NetworkClient) *VDR {
	return &VDR{
		Config:        config,
		crypto:        cryptoClient,
		network:       networkClient,
		_logger:       logging.Log(),
		store:         store.NewMemoryStore(),
		didDocCreator: NutsDocCreator{keyCreator: cryptoClient},
	}
}

// Configure initializes the db, but only when in server mode
func (r *VDR) Configure() error {
	var err error

	r.configOnce.Do(func() {
		cfg := core.NutsConfig()
		r.Config.Mode = cfg.GetEngineMode(r.Config.Mode)
		if r.Config.Mode == core.ServerEngineMode {
			if r.networkAmbassador == nil {
				r.networkAmbassador = network.NewAmbassador(r.network, r.crypto)
			}
		}
	})
	return err
}

// Start initiates the routines for auto-updating the data
func (r *VDR) Start() error {
	if r.Config.Mode == core.ServerEngineMode {
		r.networkAmbassador.Start()
	}
	return nil
}

// Shutdown cleans up any leftover go routines
func (r *VDR) Shutdown() error {
	if r.Config.Mode == core.ServerEngineMode {
		logging.Log().Debug("Sending close signal to all routines")
		for _, ch := range r.closers {
			ch <- struct{}{}
		}
		logging.Log().Info("All routines closed")
	}
	return nil
}

func (r *VDR) Diagnostics() []core.DiagnosticResult {
	return []core.DiagnosticResult{}
}

func (r *VDR) getEventsDir() string {
	return r.Config.Datadir + "/events"
}

func (r VDR) Create() (*did.Document, error) {
	doc, err := r.didDocCreator.Create()
	if err != nil {
		return nil, fmt.Errorf("could not create did document: %w", err)
	}

	// Fixme: The doc should not be stored but send to the network.
	metaData := types.DocumentMetadata{
		Created: time.Now(),
		Version: 0,
	}
	err = r.store.Write(*doc, metaData)
	if err != nil {
		return nil, fmt.Errorf("could not store created did document: %w", err)
	}
	return doc, nil
}

func (r VDR) Resolve(dID did.DID, metadata *types.ResolveMetaData) (*did.Document, *types.DocumentMetadata, error) {
	return r.store.Resolve(dID, metadata)
}

func (r VDR) Update(dID did.DID, current hash.SHA256Hash, next did.Document, metadata *types.DocumentMetadata) error {
	return r.store.Update(dID, current, next, metadata)
}

func (r *VDR) Deactivate(DID did.DID, current hash.SHA256Hash) {
	panic("implement me")
}
