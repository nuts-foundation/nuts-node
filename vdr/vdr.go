/*
 * Nuts registry
 * Copyright (C) 2020. Nuts community
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
	"sync"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-node/vdr/logging"

	"github.com/nuts-foundation/nuts-network/pkg"

	"github.com/nuts-foundation/nuts-node/vdr/network"

	networkClient "github.com/nuts-foundation/nuts-network/client"
	networkPkg "github.com/nuts-foundation/nuts-network/pkg"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
)


//type StoreWrapper struct {
//	networkClient networkPkg.NetworkClient
//	store         DIDStore
//}
//
//func wrap(store DIDStore) DIDStore {
//	return &StoreWrapper(store: store)
//}

// Registry holds the config and Db reference
type Registry struct {
	Config            Config
	//Db                db.Db
	network           networkPkg.NetworkClient
	crypto            crypto.KeyStore
	OnChange          func(registry *Registry)
	networkAmbassador network.Ambassador
	configOnce        sync.Once
	_logger           *logrus.Entry
	closers           []chan struct{}
}

var instance *Registry
var oneRegistry sync.Once

// ReloadRegistryIdleTimeout defines the cooling down period after receiving a file watcher notification, before
// the registry is reloaded (from disk).
var ReloadRegistryIdleTimeout time.Duration

func init() {
	ReloadRegistryIdleTimeout = 3 * time.Second
}

// RegistryInstance returns the singleton Registry
func RegistryInstance() *Registry {
	if instance != nil {
		return instance
	}
	oneRegistry.Do(func() {
		instance = NewRegistryInstance(DefaultRegistryConfig(), crypto.Instance(), networkClient.NewNetworkClient())
	})

	return instance
}

func NewRegistryInstance(config Config, cryptoClient crypto.KeyStore, networkClient pkg.NetworkClient) *Registry {
	return &Registry{
		Config:  config,
		crypto:  cryptoClient,
		network: networkClient,
		_logger: logging.Log(),
	}
}

// Configure initializes the db, but only when in server mode
func (r *Registry) Configure() error {
	var err error

	r.configOnce.Do(func() {
		cfg := core.NutsConfig()
		r.Config.Mode = cfg.GetEngineMode(r.Config.Mode)
		if r.Config.Mode == core.ServerEngineMode {
			//r.Db = db.New()
			if r.networkAmbassador == nil {
				r.networkAmbassador = network.NewAmbassador(r.network, r.crypto)
			}
		}
	})
	return err
}

// Start initiates the routines for auto-updating the data
func (r *Registry) Start() error {
	if r.Config.Mode == core.ServerEngineMode {
		r.networkAmbassador.Start()
	}
	return nil
}

// Shutdown cleans up any leftover go routines
func (r *Registry) Shutdown() error {
	if r.Config.Mode == core.ServerEngineMode {
		logging.Log().Debug("Sending close signal to all routines")
		for _, ch := range r.closers {
			ch <- struct{}{}
		}
		logging.Log().Info("All routines closed")
	}
	return nil
}

func (r *Registry) Diagnostics() []core.DiagnosticResult {
	return []core.DiagnosticResult{}
}

func (r *Registry) getEventsDir() string {
	return r.Config.Datadir + "/events"
}

func (r *Registry) Search(onlyOwn bool, tags []string) ([]did.Document, error) {
	panic("implement me")
}

func (r *Registry) Create() (*did.Document, error) {
	panic("implement me")
}

func (r *Registry) Get(DID did.DID) (*did.Document, *DocumentMetadata, error) {
	panic("implement me")
}

func (r *Registry) GetByTag(tag string) (*did.Document, *DocumentMetadata, error) {
	panic("implement me")
}

func (r *Registry) Update(DID did.DID, hash []byte, nextVersion did.Document) (*did.Document, error) {
	panic("implement me")
}

func (r *Registry) Tag(DID did.DID, tags []string) error {
	panic("implement me")
}
