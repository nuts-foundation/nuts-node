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

package vdr

import (
	"context"
	crypto2 "crypto"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"sync"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test the full stack by testing creating and updating DID documents.
func TestVDRIntegration_Test(t *testing.T) {
	ctx := setup(t)

	// Start with a first and fresh document named DocumentA.
	docs, _, err := ctx.vdr.Create(ctx.audit, didsubject.DefaultCreationOptions().With(didsubject.NutsLegacyNamingOption{}))
	require.NoError(t, err)
	docA := &docs[0]

	docAID := docA.ID

	// Check if the document can be found in the store
	docA, metadataDocA, err := ctx.didStore.Resolve(docAID, nil)
	require.NoError(t, err)

	assert.NotNil(t, docA)
	assert.NotNil(t, metadataDocA)
	assert.Equal(t, docAID, docAID)

	// Try to update the document with a service
	serviceID, _ := url.Parse(docAID.String() + "#service-1")
	newService := did.Service{
		ID:              ssi.URI{URL: *serviceID},
		Type:            "service",
		ServiceEndpoint: []interface{}{"http://example.com/service"},
	}

	docA.Service = append(docA.Service, newService)

	err = ctx.vdr.nutsDocumentManager.Update(ctx.audit, docAID, *docA)
	require.NoError(t, err, "unable to update docA with a new service")

	// Resolve the document and check it contents
	docA, metadataDocA, err = ctx.didStore.Resolve(docA.ID, nil)
	require.NoError(t, err, "unable to resolve updated document")
	assert.Len(t, docA.Service, 1)
	assert.Equal(t, newService, docA.Service[0],
		"expected updated docA to have a service")

	// Create a new DID Document we name DocumentB
	docs, _, err = ctx.vdr.Create(ctx.audit, didsubject.DefaultCreationOptions().With(didsubject.NutsLegacyNamingOption{}))
	require.NoError(t, err, "unexpected error while creating DocumentB")
	docB := &docs[0]
	_, _, err = ctx.didStore.Resolve(docB.ID, nil)
	assert.NoError(t, err,
		"unexpected error while resolving documentB")

	// Update and check DocumentA with a new service:
	serviceID, _ = url.Parse(docA.ID.String() + "#service-2")
	newService = did.Service{
		ID:              ssi.URI{URL: *serviceID},
		Type:            "service-2",
		ServiceEndpoint: []interface{}{"http://example.com/service2"},
	}
	docA.Service = append(docA.Service, newService)

	err = ctx.vdr.nutsDocumentManager.Update(ctx.audit, docA.ID, *docA)
	require.NoError(t, err, "unable to update documentA with a new service")
	// Resolve and check if the service has been added
	docA, metadataDocA, err = ctx.didStore.Resolve(docA.ID, nil)
	require.NoError(t, err, "unable to resolve updated documentA")
	require.Len(t, docA.Service, 2, "expected documentA to have 2 services after the update")
	assert.Equal(t, newService, docA.Service[1],
		"news service of document a does not contain expected values")

	// deactivate document B
	err = ctx.vdr.Deactivate(ctx.audit, docB.ID.String())
	require.NoError(t, err,
		"expected deactivation to succeed")

	docB, _, err = ctx.didStore.Resolve(docB.ID, &resolver.ResolveMetadata{AllowDeactivated: true})
	require.NoError(t, err)
	assert.Len(t, docB.CapabilityInvocation, 0,
		"expected document B to not have any CapabilityInvocation methods after deactivation")

	// try to deactivate the document again
	err = ctx.vdr.Deactivate(ctx.audit, docB.ID.String())
	assert.ErrorIs(t, err, resolver.ErrDeactivated,
		"expected an error when trying to deactivate an already deactivated document")
}

// Test the full stack by testing creating and updating DID documents.
func TestVDRMigration_Test(t *testing.T) {
	ctx := setup(t)

	// Start with a first and fresh document named DocumentA.
	docs, _, err := ctx.vdr.Create(ctx.audit, didsubject.DefaultCreationOptions())
	require.NoError(t, err)
	docA := &docs[0]

	// Create a new DID Document we name DocumentB
	docs, _, err = ctx.vdr.Create(ctx.audit, didsubject.DefaultCreationOptions())
	require.NoError(t, err)
	docB := &docs[0]

	// Update the controller of DocumentA with DocumentB
	docA.Controller = []did.DID{docB.ID}
	err = ctx.vdr.NutsDocumentManager().Update(ctx.audit, docA.ID, *docA)
	require.NoError(t, err, "unable to update documentA with a new controller")

	// Resolve and check DocumentA
	docA, _, err = ctx.didStore.Resolve(docA.ID, nil)
	require.NoError(t, err, "unable to resolve updated documentA")
	assert.Equal(t, []did.DID{docB.ID}, docA.Controller,
		"expected updated documentA to have documentB as its controller")

	// run migration
	err = ctx.vdr.Migrate()
	require.NoError(t, err, "migration failed")

	docA, _, err = ctx.didStore.Resolve(docA.ID, nil)
	require.NoError(t, err, "unable to resolve updated documentA")
	assert.Nil(t, docA.Controller,
		"expected updated documentA to have no controllers after migration")
	assert.NotNil(t, docA.CapabilityInvocation, "expected documentA to have CapabilityInvocation")
}

func TestVDRIntegration_ConcurrencyTest(t *testing.T) {
	ctx := setup(t)

	// Start with a first and fresh document named DocumentA.
	docs, _, err := ctx.vdr.Create(ctx.audit, didsubject.DefaultCreationOptions().With(didsubject.NutsLegacyNamingOption{}))
	require.NoError(t, err)
	initialDoc := &docs[0]

	// Check if the document can be found in the store
	_, _, err = ctx.didStore.Resolve(initialDoc.ID, nil)
	require.NoError(t, err)

	const procs = 10
	wg := sync.WaitGroup{}
	wg.Add(procs)
	currDoc, _, _ := ctx.didStore.Resolve(initialDoc.ID, nil)
	errs := make(chan error, procs)
	for i := 0; i < procs; i++ {
		go func(num int) {
			defer wg.Done()
			newDoc := *currDoc
			serviceID, _ := url.Parse(fmt.Sprintf("%s#service-%d", currDoc.ID, num))
			newService := did.Service{
				ID:              ssi.URI{URL: *serviceID},
				Type:            fmt.Sprintf("service-%d", num),
				ServiceEndpoint: []interface{}{"http://example.com/service"},
			}

			newDoc.Service = append(currDoc.Service, newService)
			err := ctx.vdr.nutsDocumentManager.Update(ctx.audit, currDoc.ID, newDoc)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()

	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
}

func TestVDRIntegration_ReprocessEvents(t *testing.T) {
	ctx := setup(t)

	// Publish a DID Document
	docs, _, _ := ctx.vdr.Create(audit.TestContext(), didsubject.DefaultCreationOptions().With(didsubject.NutsLegacyNamingOption{}))
	didDoc := &docs[0]
	kid := didDoc.VerificationMethod[0].ID.String()
	publicKey, _ := didDoc.VerificationMethod[0].PublicKey()
	payload, _ := json.Marshal(didDoc)
	unsignedTransaction, _ := dag.NewTransaction(hash.SHA256Sum(payload), didnuts.DIDDocumentType, nil, nil, uint32(0))
	signedTransaction, err := dag.NewTransactionSigner(ctx.cryptoInstance, kid, publicKey).Sign(audit.TestContext(), unsignedTransaction, time.Now())
	require.NoError(t, err)
	twp := events.TransactionWithPayload{
		Transaction: signedTransaction,
		Payload:     payload,
	}
	twpBytes, _ := json.Marshal(twp)

	_, js, _ := ctx.eventPublisher.Pool().Acquire(context.Background())
	_, err = js.Publish("REPROCESS.application/did+json", twpBytes)

	require.NoError(t, err)

	test.WaitFor(t, func() (bool, error) {
		_, _, err := ctx.didStore.Resolve(didDoc.ID, nil)
		return err == nil, nil
	}, 5*time.Second, "timeout while waiting for event to be processed")
}

type testContext struct {
	vdr             *Module
	eventPublisher  events.Event
	didStore        didstore.Store
	cryptoInstance  *crypto.Crypto
	audit           context.Context
	storageInstance storage.Engine
}

func setup(t *testing.T) testContext {
	// === Setup ===
	testDir := io.TestDirectory(t)
	nutsConfig := core.TestServerConfig(func(config *core.ServerConfig) {
		config.Strictmode = false
		config.Verbosity = "trace"
		config.Datadir = testDir
		config.DIDMethods = []string{"nuts"}
	})

	// Configure the logger:
	var lvl log.Level
	var err error
	// initialize logger, verbosity flag needs to be available
	if lvl, err = log.ParseLevel(nutsConfig.Verbosity); err != nil {
		t.Fatal(err)
	}
	log.SetLevel(lvl)
	log.SetFormatter(&log.TextFormatter{ForceColors: true})

	// Storage
	storageEngine := storage.NewTestStorageEngine(t)

	// Startup crypto
	cryptoInstance := crypto.NewCryptoInstance(storageEngine)
	require.NoError(t, cryptoInstance.Configure(nutsConfig))

	// DID Store
	didStore := didstore.TestStore(t, storageEngine)

	// Startup events
	eventPublisher := events.NewTestManager(t)

	// Create PKI engine
	pkiValidator := pki.New()
	require.NoError(t, pkiValidator.Configure(nutsConfig))
	// is not pkiValidator.Start()-ed

	// Create instances
	networkCfg := network.DefaultConfig()
	networkCfg.GrpcAddr = "localhost:5555"
	nutsNetwork := network.NewNetworkInstance(
		networkCfg,
		didStore,
		cryptoInstance,
		eventPublisher,
		storageEngine.GetProvider("network"),
		pkiValidator,
	)
	vdr := NewVDR(cryptoInstance, nutsNetwork, didStore, eventPublisher, storageEngine)

	// Configure
	require.NoError(t, vdr.Configure(nutsConfig))
	require.NoError(t, nutsNetwork.Configure(nutsConfig))

	// Start
	require.NoError(t, vdr.Start())
	t.Cleanup(func() {
		_ = vdr.Shutdown()
	})
	require.NoError(t, nutsNetwork.Start())
	t.Cleanup(func() {
		_ = nutsNetwork.Shutdown()
	})

	return testContext{
		vdr:             vdr,
		eventPublisher:  eventPublisher,
		didStore:        didStore,
		cryptoInstance:  cryptoInstance,
		audit:           audit.TestContext(),
		storageInstance: storageEngine,
	}
}

// testKey is temporary and will be removed by a future PR
type testKey struct {
	kid       string
	publicKey crypto2.PublicKey
}

func (t testKey) KID() string {
	return t.kid
}

func (t testKey) Public() crypto2.PublicKey {
	return t.publicKey
}
