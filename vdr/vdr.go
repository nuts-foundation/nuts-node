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

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/vdr/log"

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
		_logger:           log.Logger(),
		store:             store,
		didDocCreator:     doc.Creator{KeyStore: cryptoClient},
		didDocResolver:    doc.Resolver{Store: store},
		networkAmbassador: NewAmbassador(networkClient, store),
		keyStore:          cryptoClient,
	}
}

func (r *VDR) Name() string {
	return moduleName
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

func (r *VDR) ConflictedDocuments() ([]did.Document, []types.DocumentMetadata, error) {
	conflictedDocs := make([]did.Document, 0)
	conflictedMeta := make([]types.DocumentMetadata, 0)

	err := r.store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
		if metadata.IsConflicted() {
			conflictedDocs = append(conflictedDocs, doc)
			conflictedMeta = append(conflictedMeta, metadata)
		}
		return nil
	})
	return conflictedDocs, conflictedMeta, err
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
			Title:   "conflicted_did_documents_count",
			Outcome: count,
		},
	}
}

// Create generates a new DID Document
func (r VDR) Create(options types.DIDCreationOptions) (*did.Document, crypto.Key, error) {
	log.Logger().Debug("Creating new DID Document.")
	doc, key, err := r.didDocCreator.Create(options)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create DID document: %w", err)
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}

	tx := network.TransactionTemplate(didDocumentType, payload, key).WithAttachKey()
	_, err = r.network.CreateTransaction(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not store DID document in network: %w", err)
	}

	log.Logger().Infof("New DID Document created (DID=%s)", doc.ID)

	return doc, key, nil
}

// Update updates a DID Document based on the DID and current hash
func (r VDR) Update(id did.DID, current hash.SHA256Hash, next did.Document, _ *types.DocumentMetadata) error {
	log.Logger().Debugf("Updating DID Document (DID=%s)", id)
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

	if err = CreateDocumentValidator().Validate(next); err != nil {
		return err
	}

	payload, err := json.Marshal(next)
	if err != nil {
		return err
	}

	controller, key, err := r.resolveControllerWithKey(*currentDIDDocument)
	if err != nil {
		return err
	}

	// for the metadata
	_, controllerMeta, err := r.didDocResolver.Resolve(controller.ID, nil)
	if err != nil {
		return err
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	tx := network.TransactionTemplate(didDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
	_, err = r.network.CreateTransaction(tx)
	if err == nil {
		log.Logger().Infof("DID Document updated (DID=%s)", id)
	} else {
		log.Logger().WithError(err).Warn("Unable to update DID document")
		if errors.Is(err, crypto.ErrKeyNotFound) {
			return types.ErrDIDNotManagedByThisNode
		}
	}

	return err
}

func (r VDR) resolveControllerWithKey(doc did.Document) (did.Document, crypto.Key, error) {
	controllers, err := r.didDocResolver.ResolveControllers(doc, nil)
	if err != nil {
		return did.Document{}, nil, fmt.Errorf("error while finding controllers for document: %w", err)
	}
	if len(controllers) == 0 {
		return did.Document{}, nil, fmt.Errorf("could not find any controllers for document")
	}

	var key crypto.Key
	for _, c := range controllers {
		for _, cik := range c.CapabilityInvocation {
			key, err = r.keyStore.Resolve(cik.ID.String())
			if err == nil {
				return c, key, nil
			}
		}
	}

	if errors.Is(err, crypto.ErrKeyNotFound) {
		return did.Document{}, nil, types.ErrDIDNotManagedByThisNode
	}

	return did.Document{}, nil, fmt.Errorf("could not find capabilityInvocation key for updating the DID document: %w", err)
}

func (r *VDR) Find(predicate ...types.Predicate) ([]did.Document, error) {
	matches := make([]did.Document, 0)

	err := r.store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
		for _, p := range predicate {
			if !p.Match(doc, metadata) {
				return nil
			}
		}
		matches = append(matches, doc)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return matches, err
}
