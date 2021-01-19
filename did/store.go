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

package did

import (
	"sync"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-network/pkg/model"
	"github.com/nuts-foundation/nuts-node/did/logging"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-network/pkg"
	"github.com/nuts-foundation/nuts-node/did/network"

	"github.com/nuts-foundation/nuts-node/core"
	networkClient "github.com/nuts-foundation/nuts-network/client"
	networkPkg "github.com/nuts-foundation/nuts-network/pkg"
	"github.com/nuts-foundation/nuts-node/crypto"
)

// ConfDataDir is the config name for specifiying the data location of the requiredFiles
const ConfDataDir = "datadir"

// ConfMode is the config name for the engine mode, server or client
const ConfMode = "mode"

// ConfAddress is the config name for the http server/client address
const ConfAddress = "address"

// ConfSyncMode is the config name for the used SyncMode
const ConfSyncMode = "syncMode"

// ConfSyncAddress is the config name for the remote address used to fetch updated registry files
const ConfSyncAddress = "syncAddress"

// ConfSyncInterval is the config name for the interval in minutes to look for new registry files online
const ConfSyncInterval = "syncInterval"

// ConfOrganisationCertificateValidity is the config name for the number of days organisation certificates are valid
const ConfOrganisationCertificateValidity = "organisationCertificateValidity"

// ConfVendorCACertificateValidity is the config name for the number of days vendor CA certificates are valid
const ConfVendorCACertificateValidity = "vendorCACertificateValidity"

// ConfClientTimeout is the time-out for the client in seconds (e.g. when using the CLI).
const ConfClientTimeout = "clientTimeout"

// ModuleName == Registry
const ModuleName = "Registry"

// ReloadRegistryIdleTimeout defines the cooling down period after receiving a file watcher notification, before
// the registry is reloaded (from disk).
var ReloadRegistryIdleTimeout time.Duration

// Store is the interface for the low level DID operations.
type Store interface {
	// Search searches for DID documents that match the given conditions;
	// - onlyOwn: only return documents which contain a verificationMethod which' private key is present in this node.
	// - tags: only return documents that match ALL of the given tags.
	// If something goes wrong an error is returned.
	Search(onlyOwn bool, tags []string) ([]did.Document, error)
	// Create creates a new DID document and returns it. If something goes wrong an error is returned.
	Create() (*did.Document, error)
	// Get returns the DID document using on the given DID or nil if not found. If something goes wrong an error is returned.
	Get(DID did.DID) (*did.Document, *DocumentMetadata, error)
	// GetByTag gets a DID document using the given tag or nil if not found. If multiple documents match the given tag
	// or something else goes wrong, an error is returned.
	GetByTag(tag string) (*did.Document, *DocumentMetadata, error)
	// Update replaces the DID document identified by DID with the nextVersion if the given hash matches the current valid DID document hash.
	Update(DID did.DID, hash []byte, nextVersion did.Document) (*did.Document, error)
	// Tag replaces all tags on a DID document given the DID.
	Tag(DID did.DID, tags []string) error
}

// DocumentMetadata holds the metadata of a DID document
type DocumentMetadata struct {
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated,omitempty"`
	// Version contains the semantic version of the DID document.
	Version int `json:"version"`
	// OriginJWSHash contains the hash of the JWS envelope of the first version of the DID document.
	OriginJWSHash model.Hash `json:"originJwsHash"`
	// Hash of DID document bytes. Is equal to payloadHash in network layer.
	Hash string `json:"hash"`
	// Tags of the DID document.
	Tags []string `json:"tags,omitempty"`
}

//type StoreWrapper struct {
//	networkClient networkPkg.NetworkClient
//	store         DIDStore
//}
//
//func wrap(store DIDStore) DIDStore {
//	return &StoreWrapper(store: store)
//}

// Config holds the config
type Config struct {
	Mode          string
	Datadir       string
	Address       string
	ClientTimeout int
}

func DefaultRegistryConfig() Config {
	return Config{
		Datadir:       "./data",
		Address:       "localhost:1323",
		ClientTimeout: 10,
	}
}

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
