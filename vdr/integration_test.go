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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
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
	"github.com/nuts-foundation/nuts-node/vdr/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test the full stack by testing creating and updating DID documents.
func TestVDRIntegration_Test(t *testing.T) {
	ctx := setup(t)

	// Start with a first and fresh document named DocumentA.
	docA, _, err := ctx.vdr.Create(ctx.audit, didnuts.DefaultCreationOptions())
	require.NoError(t, err)
	assert.NotNil(t, docA)

	docAID := docA.ID

	// Check if the document can be found in the store
	docA, metadataDocA, err := ctx.didResolver.Resolve(docA.ID, nil)
	require.NoError(t, err)

	assert.NotNil(t, docA)
	assert.NotNil(t, metadataDocA)
	assert.Equal(t, docAID, docA.ID)

	// Try to update the document with a service
	serviceID, _ := url.Parse(docA.ID.String() + "#service-1")
	newService := did.Service{
		ID:              ssi.URI{URL: *serviceID},
		Type:            "service",
		ServiceEndpoint: []interface{}{"http://example.com/service"},
	}

	docA.Service = append(docA.Service, newService)

	err = ctx.vdr.Update(ctx.audit, docAID, *docA)
	require.NoError(t, err, "unable to update docA with a new service")

	// Resolve the document and check it contents
	docA, metadataDocA, err = ctx.didResolver.Resolve(docA.ID, nil)
	require.NoError(t, err, "unable to resolve updated document")
	assert.Len(t, docA.Service, 1)
	assert.Equal(t, newService, docA.Service[0],
		"expected updated docA to have a service")

	// Create a new DID Document we name DocumentB
	docB, _, err := ctx.vdr.Create(ctx.audit, didnuts.DefaultCreationOptions())
	require.NoError(t, err, "unexpected error while creating DocumentB")
	assert.NotNil(t, docB,
		"a new document should have been created")
	_, _, err = ctx.didResolver.Resolve(docB.ID, nil)
	assert.NoError(t, err,
		"unexpected error while resolving documentB")

	// Update the controller of DocumentA with DocumentB
	// And remove its own authenticationMethod
	docA.Controller = []did.DID{docB.ID}
	docA.AssertionMethod = []did.VerificationRelationship{}
	docA.CapabilityInvocation = []did.VerificationRelationship{}
	docA.VerificationMethod = []*did.VerificationMethod{}
	docA.KeyAgreement = []did.VerificationRelationship{}
	err = ctx.vdr.Update(ctx.audit, docAID, *docA)
	require.NoError(t, err, "unable to update documentA with a new controller")

	// Resolve and check DocumentA
	docA, metadataDocA, err = ctx.didResolver.Resolve(docA.ID, nil)
	require.NoError(t, err, "unable to resolve updated documentA")
	assert.Equal(t, []did.DID{docB.ID}, docA.Controller,
		"expected updated documentA to have documentB as its controller")

	assert.Empty(t, docA.CapabilityInvocation,
		"expected documentA to have no CapabilityInvocation")

	// Update and check DocumentA with a new service:
	serviceID, _ = url.Parse(docA.ID.String() + "#service-2")
	newService = did.Service{
		ID:              ssi.URI{URL: *serviceID},
		Type:            "service-2",
		ServiceEndpoint: []interface{}{"http://example.com/service2"},
	}
	docA.Service = append(docA.Service, newService)

	err = ctx.vdr.Update(ctx.audit, docA.ID, *docA)
	require.NoError(t, err, "unable to update documentA with a new service")
	// Resolve and check if the service has been added
	docA, metadataDocA, err = ctx.didResolver.Resolve(docA.ID, nil)
	require.NoError(t, err, "unable to resolve updated documentA")
	require.Len(t, docA.Service, 2, "expected documentA to have 2 services after the update")
	assert.Equal(t, newService, docA.Service[1],
		"news service of document a does not contain expected values")

	// deactivate document B
	docUpdater := &didnuts.Manipulator{KeyCreator: ctx.cryptoInstance, Updater: ctx.vdr, Resolver: ctx.didResolver}
	err = docUpdater.Deactivate(ctx.audit, docB.ID)
	assert.NoError(t, err,
		"expected deactivation to succeed")

	docB, _, err = ctx.didResolver.Resolve(docB.ID, &types.ResolveMetadata{AllowDeactivated: true})
	assert.NoError(t, err)
	assert.Len(t, docB.CapabilityInvocation, 0,
		"expected document B to not have any CapabilityInvocation methods after deactivation")

	// try to deactivate the document again
	err = docUpdater.Deactivate(ctx.audit, docB.ID)
	assert.ErrorIs(t, err, types.ErrDeactivated,
		"expected an error when trying to deactivate an already deactivated document")

	// try to update document A should fail since it no longer has an active controller
	docA.Service = docA.Service[1:]
	err = ctx.vdr.Update(ctx.audit, docAID, *docA)
	assert.EqualError(t, err, "update DID document: could not find any controllers for document")
}

func TestVDRIntegration_ConcurrencyTest(t *testing.T) {
	ctx := setup(t)

	// Start with a first and fresh document named DocumentA.
	initialDoc, _, err := ctx.vdr.Create(ctx.audit, didnuts.DefaultCreationOptions())
	require.NoError(t, err)
	assert.NotNil(t, initialDoc)

	// Check if the document can be found in the store
	initialDoc, _, err = ctx.didResolver.Resolve(initialDoc.ID, nil)
	require.NoError(t, err)

	const procs = 10
	wg := sync.WaitGroup{}
	wg.Add(procs)
	currDoc, _, _ := ctx.didResolver.Resolve(initialDoc.ID, nil)
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
			err := ctx.vdr.Update(ctx.audit, currDoc.ID, newDoc)
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
	didDoc, key, _ := ctx.docCreator.Create(audit.TestContext(), didnuts.DefaultCreationOptions())
	payload, _ := json.Marshal(didDoc)
	unsignedTransaction, _ := dag.NewTransaction(hash.SHA256Sum(payload), didnuts.DIDDocumentType, nil, nil, uint32(0))
	signedTransaction, err := dag.NewTransactionSigner(ctx.cryptoInstance, key, true).Sign(audit.TestContext(), unsignedTransaction, time.Now())
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
		_, _, err := ctx.didResolver.Resolve(didDoc.ID, nil)
		return err == nil, nil
	}, 5*time.Second, "timeout while waiting for event to be processed")
}

type testContext struct {
	vdr            *VDR
	eventPublisher events.Event
	docCreator     types.DocCreator
	didResolver    types.DIDResolver
	cryptoInstance *crypto.Crypto
	audit          context.Context
}

func setup(t *testing.T) testContext {
	// === Setup ===
	testDir := io.TestDirectory(t)
	nutsConfig := *core.NewServerConfig()
	nutsConfig.Verbosity = "debug"
	nutsConfig.Datadir = testDir

	// Configure the logger:
	var lvl log.Level
	var err error
	// initialize logger, verbosity flag needs to be available
	if lvl, err = log.ParseLevel(nutsConfig.Verbosity); err != nil {
		t.Fatal(err)
	}
	log.SetLevel(lvl)
	log.SetFormatter(&log.TextFormatter{ForceColors: true})

	// Startup crypto
	cryptoInstance := crypto.NewCryptoInstance()
	require.NoError(t, cryptoInstance.Configure(nutsConfig))

	// Storage
	storageEngine := storage.NewTestStorageEngine(io.TestDirectory(t))

	// DID Resolver
	didResolver := &didservice.DIDResolverRouter{}

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
		didResolver,
		cryptoInstance,
		eventPublisher,
		storageEngine.GetProvider("network"),
		pkiValidator,
	)
	vdr := NewVDR(storageEngine.GetProvider("vdr"), cryptoInstance, nutsNetwork, didResolver, eventPublisher)

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
		vdr:            vdr,
		eventPublisher: eventPublisher,
		docCreator:     vdr.didDocCreator,
		didResolver:    didResolver,
		cryptoInstance: cryptoInstance,
		audit:          audit.TestContext(),
	}
}
