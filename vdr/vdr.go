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
	"errors"
	"fmt"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/vdr/logging"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// VDR stands for the Nuts Verifiable Data Registry. It is the public entrypoint to work with W3C DID documents.
// It connects the Resolve, Create and Update DID methods to the network, and receives events back from the network which are processed in the store.
// It is also a Runnable, Diagnosable and Configurable Nuts Engine.
type VDR struct {
	config            Config
	store             types.Store
	network           network.Transactions
	OnChange          func(registry *VDR)
	networkAmbassador Ambassador
	_logger           *logrus.Entry
	didDocCreator     types.DocCreator
	didDocResolver    types.DocResolver
	keyStore          crypto.KeyStore
}

// NewVDR creates a new VDR with provided params
func NewVDR(config Config, cryptoClient crypto.KeyStore, networkClient network.Transactions, store types.Store) *VDR {
	return &VDR{
		config:            config,
		network:           networkClient,
		_logger:           logging.Log(),
		store:             store,
		didDocCreator:     doc.Creator{KeyCreator: cryptoClient},
		didDocResolver:    doc.Resolver{Store: store},
		networkAmbassador: NewAmbassador(networkClient, store),
		keyStore:          cryptoClient,
	}
}

func (r *VDR) Name() string {
	return moduleName
}

func (r *VDR) ConfigKey() string {
	return configKey
}

func (r *VDR) Config() interface{} {
	return &r.config
}

// Configure configures the VDR engine.
func (r *VDR) Configure(_ core.ServerConfig) error {
	// Initiate the routines for auto-updating the data.
	r.networkAmbassador.Configure()
	return nil
}

// Diagnostics returns the diagnostics for this engine
func (r *VDR) Diagnostics() []core.DiagnosticResult {
	// return # conflicted docs
	count := 0
	r.store.Iterate(func(_ did.Document, metadata types.DocumentMetadata) error {
		if metadata.IsConflicted() {
			count++
		}
		return nil
	})

	return []core.DiagnosticResult{
		&core.GenericDiagnosticResult{
			Title:   "# Conflicted DID Documents",
			Outcome: fmt.Sprintf("%d", count),
		},
	}
}

// Create generates a new DID Document
func (r VDR) Create() (*did.Document, error) {
	logging.Log().Debug("Creating new DID Document.")
	doc, err := r.didDocCreator.Create()
	if err != nil {
		return nil, fmt.Errorf("could not create did document: %w", err)
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	keyID := doc.CapabilityInvocation[0].ID.String()
	key, err := doc.CapabilityInvocation[0].PublicKey()
	if err != nil {
		return nil, err
	}
	_, err = r.network.CreateTransaction(didDocumentType, payload, keyID, key, time.Now(), []hash.SHA256Hash{})
	if err != nil {
		return nil, fmt.Errorf("could not store did document in network: %w", err)
	}

	logging.Log().Infof("New DID Document created (DID=%s)", doc.ID)

	return doc, nil
}

// Update updates a DID Document based on the DID and current hash
func (r VDR) Update(id did.DID, current hash.SHA256Hash, next did.Document, _ *types.DocumentMetadata) error {
	logging.Log().Debugf("Updating DID Document (DID=%s)", id)
	// TODO: check the integrity / validity of the proposed DID Document.
	resolverMetadata := &types.ResolveMetadata{
		Hash:             &current,
		AllowDeactivated: true,
	}
	currentDIDDocument, currentMeta, err := r.store.Resolve(id, resolverMetadata)
	if err != nil {
		return err
	}
	if store.IsDeactivated(*currentDIDDocument) {
		return types.ErrDeactivated
	}
	controllers, err := r.didDocResolver.ResolveControllers(*currentDIDDocument)
	if err != nil {
		return fmt.Errorf("error while finding controllers for document: %w", err)
	}
	if len(controllers) == 0 {
		return fmt.Errorf("could not find any controllers for document")
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}

	keyID := controllers[0].CapabilityInvocation[0].ID.String()
	_, err = r.network.CreateTransaction(didDocumentType, payload, keyID, nil, time.Now(), currentMeta.SourceTransactions)
	if err == nil {
		logging.Log().Infof("DID Document updated (DID=%s)", id)
	} else {
		logging.Log().WithError(err).Warn("Unable to update DID document")
		if errors.Is(err, crypto.ErrKeyNotFound) {
			return types.ErrDIDNotManagedByThisNode
		}
	}

	return err
}
