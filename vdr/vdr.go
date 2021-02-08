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
	"encoding/json"
	"fmt"
	"time"

	"github.com/nuts-foundation/nuts-node/network/dag"
	networkTypes "github.com/nuts-foundation/nuts-node/network/types"
	"github.com/nuts-foundation/nuts-node/vdr/store"

	"github.com/nuts-foundation/go-did"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/vdr/logging"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	crypto "github.com/nuts-foundation/nuts-node/crypto/types"
	api "github.com/nuts-foundation/nuts-node/vdr/api/v1"
)

// VDR stands for the Nuts Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type VDR struct {
	config            Config
	store             types.Store
	network           networkTypes.Transactions
	OnChange          func(registry *VDR)
	networkAmbassador Ambassador
	_logger           *logrus.Entry
	didDocCreator     types.DocCreator
}

// NewVDR creates a new VDR with provided params
func NewVDR(config Config, cryptoClient crypto.KeyStore, networkClient networkTypes.Transactions) *VDR {
	store := store.NewMemoryStore()
	return &VDR{
		config:            config,
		network:           networkClient,
		_logger:           logging.Log(),
		store:             store,
		didDocCreator:     NutsDocCreator{keyCreator: cryptoClient},
		networkAmbassador: NewAmbassador(networkClient, store, cryptoClient),
	}
}

func (r *VDR) Name() string {
	return engineName
}

func (r *VDR) ConfigKey() string {
	return configKey
}

func (r *VDR) Config() interface{} {
	return &r.config
}

// Start initiates the routines for auto-updating the data
func (r *VDR) Start() error {
	r.networkAmbassador.Start()
	return nil
}

// Shutdown cleans up any leftover go routines
func (r *VDR) Shutdown() error {
	return nil
}

// Diagnostics returns the diagnostics for this engine
func (r *VDR) Diagnostics() []core.DiagnosticResult {
	return []core.DiagnosticResult{}
}

func (r *VDR) Routes(router core.EchoRouter) {
	api.RegisterHandlers(router, &api.Wrapper{VDR: r})
}

// Create generates a new DID Document
func (r VDR) Create() (*did.Document, error) {
	doc, err := r.didDocCreator.Create()
	if err != nil {
		return nil, fmt.Errorf("could not create did document: %w", err)
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	keyID := doc.Authentication[0].ID.String()
	_, err = r.network.CreateDocument(didDocumentType, payload, keyID, true, time.Now())
	if err != nil {
		return nil, fmt.Errorf("could not store did document in network: %w", err)
	}

	return doc, nil
}

// Resolve resolves a DID Document based on the DID.
func (r VDR) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	return r.store.Resolve(id, metadata)
}

// Update updates a DID Document based on the DID and current hash
func (r VDR) Update(id did.DID, current hash.SHA256Hash, next did.Document, _ *types.DocumentMetadata) error {
	// TODO: check the integrity / validity of the proposed DID Document.
	resolverMetada := &types.ResolveMetadata{
		Hash:             &current,
		AllowDeactivated: false,
	}
	currentDIDdocument, meta, err := r.store.Resolve(id, resolverMetada)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}

	// TODO: look into the controller of the did for a signing key
	keyID := currentDIDdocument.Authentication[0].ID.String()
	_, err = r.network.CreateDocument(didDocumentType, payload, keyID, false, time.Now(), dag.TimelineIDField(meta.TimelineID), dag.TimelineVersionField(meta.Version+1))
	return err
}

// Deactivate updates the DID Document so it can no longer be updated
func (r *VDR) Deactivate(DID did.DID, current hash.SHA256Hash) {
	panic("implement me")
}
