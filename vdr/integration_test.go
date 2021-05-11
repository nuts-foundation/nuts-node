package vdr

import (
	"io/ioutil"
	"net/url"
	"os"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/core"
	crypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// Test the full stack by testing creating and updating did documents.
func TestVDRIntegration_Test(t *testing.T) {
	// === Setup ===
	tmpDir, err := ioutil.TempDir("", "nuts-vdr-integration-test")
	if !assert.NoError(t, err, "unable to create temporary data dir for integration test") {
		return
	}
	defer os.RemoveAll(tmpDir)
	nutsConfig := core.ServerConfig{
		Verbosity: "debug",
		Datadir:   tmpDir,
	}
	// Configure the logger:
	var lvl log.Level
	// initialize logger, verbosity flag needs to be available
	if lvl, err = log.ParseLevel(nutsConfig.Verbosity); err != nil {
		return
	}
	log.SetLevel(lvl)
	log.SetFormatter(&log.TextFormatter{ForceColors: true})

	// Startup crypto
	nutsCrypto := crypto.NewCryptoInstance()
	nutsCrypto.Configure(nutsConfig)

	// DID Store
	didStore := store.NewMemoryStore()

	// Startup the network layer
	nutsNetwork := network.NewNetworkInstance(network.DefaultConfig(), doc.KeyResolver{Store: didStore})
	nutsNetwork.Configure(nutsConfig)
	nutsNetwork.Start()

	// Init the VDR
	vdr := NewVDR(DefaultConfig(), nutsCrypto, nutsNetwork, didStore)
	vdr.Configure(nutsConfig)

	// Resolver
	docResolver := doc.Resolver{Store: didStore}

	// === End of setup ===

	// Start with a first and fresh document named DocumentA.
	docA, _, err := vdr.Create(doc.DefaultCreationOptions())
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, docA)

	docAID := docA.ID

	// Check if the document can be found in the store
	docA, metadataDocA, err := docResolver.Resolve(docA.ID, nil)
	if !assert.NoError(t, err) {
		return
	}

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

	err = vdr.Update(docAID, metadataDocA.Hash, *docA, nil)
	if !assert.NoError(t, err,
		"unable to update docA with a new service") {
		return
	}

	// Resolve the document and check it contents
	docA, metadataDocA, err = docResolver.Resolve(docA.ID, nil)
	if !assert.NoError(t, err,
		"unable to resolve updated document") {
		return
	}
	assert.Len(t, docA.Service, 1)
	assert.Equal(t, newService, docA.Service[0],
		"expected updated docA to have a service")

	// Create a new DID Document we name DocumentB
	docB, _, err := vdr.Create(doc.DefaultCreationOptions())
	if !assert.NoError(t, err,
		"unexpected error while creating DocumentB") {
		return
	}
	assert.NotNil(t, docB,
		"a new document should have been created")
	resolvedDocB, metadataDocB, err := docResolver.Resolve(docB.ID, nil)
	assert.NoError(t, err,
		"unexpected error while resolving documentB")

	// Update the controller of DocumentA with DocumentB
	// And remove it's own authenticationMethod
	docA.Controller = []did.DID{docB.ID}
	docA.AssertionMethod = []did.VerificationRelationship{}
	docA.CapabilityInvocation = []did.VerificationRelationship{}
	docA.VerificationMethod = []*did.VerificationMethod{}
	err = vdr.Update(docAID, metadataDocA.Hash, *docA, nil)
	if !assert.NoError(t, err,
		"unable to update documentA with a new controller") {
		return
	}

	// Resolve and check DocumentA
	docA, metadataDocA, err = docResolver.Resolve(docA.ID, nil)
	if !assert.NoError(t, err,
		"unable to resolve updated documentA") {
		return
	}
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

	err = vdr.Update(docA.ID, metadataDocA.Hash, *docA, nil)
	if !assert.NoError(t, err,
		"unable to update documentA with a new service") {
		return
	}
	// Resolve and check if the service has been added
	docA, metadataDocA, err = docResolver.Resolve(docA.ID, nil)
	if !assert.NoError(t, err,
		"unable to resolve updated documentA") {
		return
	}
	if !assert.Len(t, docA.Service, 2,
		"expected documentA to have 2 services after the update") {
		return
	}
	assert.Equal(t, newService, docA.Service[1],
		"news service of document a does not contain expected values")

	// Update document B with a new authentication key which replaces the first one:
	oldAuthKeyDocB := resolvedDocB.CapabilityInvocation[0].ID
	docUpdater := &doc.Manipulator{KeyCreator: nutsCrypto, Updater: *vdr, Resolver: docResolver}
	method, err := doc.CreateNewVerificationMethodForDID(docB.ID, nutsCrypto)
	assert.NoError(t, err)
	assert.NotNil(t, method)
	docB.AddCapabilityInvocation(method)
	docB.AssertionMethod.Remove(oldAuthKeyDocB)
	docB.CapabilityInvocation.Remove(oldAuthKeyDocB)
	docB.VerificationMethod.Remove(oldAuthKeyDocB)
	err = vdr.Update(docB.ID, metadataDocB.Hash, *docB, nil)
	if !assert.NoError(t, err,
		"unable to update documentB with a new CapabilityInvocation") {
		return
	}

	// Resolve document B and check if the key has been updated
	resolvedDocB, metadataDocB, err = docResolver.Resolve(docB.ID, nil)
	assert.NoError(t, err,
		"expected DocumentB to be resolved without error")

	assert.Len(t, resolvedDocB.CapabilityInvocation, 1)
	assert.NotEqual(t, oldAuthKeyDocB, resolvedDocB.CapabilityInvocation[0].ID)

	// deactivate document B
	err = docUpdater.Deactivate(docB.ID)
	assert.NoError(t, err,
		"expected deactivation to succeed")

	docB, metadataDocB, err = docResolver.Resolve(docB.ID, &types.ResolveMetadata{AllowDeactivated: true})
	assert.NoError(t, err)
	assert.Len(t, docB.CapabilityInvocation, 0,
		"expected document B to not have any CapabilityInvocation methods after deactivation")

	// try to deactivate the document again
	err = docUpdater.Deactivate(docB.ID)
	assert.EqualError(t, err, "the DID document has been deactivated",
		"expected an error when trying to deactivate an already deactivated document")

	// try to update document A should fail since it no longer has an active controller
	docA.Service = docA.Service[1:]
	err = vdr.Update(docAID, metadataDocA.Hash, *docA, nil)
	assert.EqualError(t, err, "could not find any controllers for document")

}
