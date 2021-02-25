package vdr

import (
	"io/ioutil"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/core"
	crypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
)

func TestVDRIntegration_Test(t *testing.T) {
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

	// Startup the network layer
	nutsNetwork := network.NewNetworkInstance(network.DefaultConfig(), nutsCrypto)
	nutsNetwork.Configure(nutsConfig)
	nutsNetwork.Start()

	// Init the VDR
	vdr := NewVDR(DefaultConfig(), nutsCrypto, nutsNetwork)
	vdr.Configure(nutsConfig)

	// Start with a first and fresh document named DocumentA.
	docA, err := vdr.Create()
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, docA)

	// Check if the document can be found in the store
	resolvedDoc, metadataDocA, err := vdr.Resolve(docA.ID, nil)

	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, resolvedDoc)
	assert.NotNil(t, metadataDocA)
	assert.Equal(t, docA.ID, resolvedDoc.ID)

	// Check if the public key is added to the store
	docAAuthenticationKeyID := resolvedDoc.Authentication[0].ID.String()
	key, err := nutsCrypto.GetPublicKey(docAAuthenticationKeyID, time.Now())
	assert.NoError(t, err,
		"unable to get the public key of document a from the keyStore")
	assert.NotNil(t, key,
		"key should be stored in the public key store")

	// Try to update the document with a service
	serviceID, _ := url.Parse(docA.ID.String() + "#service-1")

	docA.Service = append(docA.Service, did.Service{
		ID:              did.URI{URL: *serviceID},
		Type:            "service",
		ServiceEndpoint: []interface{}{"http://example.com/service"},
	})

	err = vdr.Update(docA.ID, metadataDocA.Hash, *docA, nil)
	if !assert.NoError(t, err,
		"unable to update docA with a new service") {
		return
	}

	// Resolve the document and check it contents
	resolvedDoc, metadataDocA, err = vdr.Resolve(docA.ID, nil)
	if !assert.NoError(t, err,
		"unable to resolve updated document") {
		return
	}
	assert.Equal(t, docA.Service[0], resolvedDoc.Service[0],
		"expected updated docA to have a service")

	// Create a new DID Document we name DocumentB
	docB, err := vdr.Create()
	if !assert.NoError(t, err,
		"unexpected error while creating DocumentB") {
		return
	}
	assert.NotNil(t, docB,
		"a new document should have been created")
	resolvedDoc, metadataDocB, err := vdr.Resolve(docB.ID, nil)
	assert.NoError(t, err,
		"unexpected error while resolving documentB")

	// Update the controller of DocumentA with DocumentB
	// And remove it's own authenticationMethod
	docA.Controller = []did.DID{docB.ID}
	// FIXME: add helper method to did lib to conveniently remove various verificationMethods
	docA.Authentication = []did.VerificationRelationship{}
	docA.VerificationMethod = []*did.VerificationMethod{}
	err = vdr.Update(docA.ID, metadataDocA.Hash, *docA, nil)
	if !assert.NoError(t, err,
		"unable to update documentA with a new controller") {
		return
	}

	// Resolve and check DocumentA
	resolvedDoc, metadataDocA, err = vdr.Resolve(docA.ID, nil)
	if !assert.NoError(t, err,
		"unable to resolve updated documentA") {
		return
	}
	assert.Equal(t, []did.DID{docB.ID}, resolvedDoc.Controller,
		"expected updated documentA to have documentB as its controller")

	assert.Empty(t, resolvedDoc.Authentication,
		"expected documentA to have no authenticationMethods")

	// Check if the key has been removed from the keyStore
	key, err = nutsCrypto.GetPublicKey(docAAuthenticationKeyID, time.Now())
	assert.EqualError(t, err, "key not found",
		"expected authenticationKey of documentA to be removed from the keyStore")

	// Update and check DocumentA with a new service:
	serviceID, _ = url.Parse(docA.ID.String() + "#service-2")
	docA.Service = append(docA.Service, did.Service{
		ID:              did.URI{URL: *serviceID},
		Type:            "service-2",
		ServiceEndpoint: []interface{}{"http://example.com/service2"},
	})
	err = vdr.Update(docA.ID, metadataDocA.Hash, *docA, nil)
	if !assert.NoError(t, err,
		"unable to update documentA with a new service") {
		return
	}
	// Resolve and check
	resolvedDoc, metadataDocA, err = vdr.Resolve(docA.ID, nil)
	if !assert.NoError(t, err,
		"unable to resolve updated documentA") {
		return
	}
	if !assert.Len(t, resolvedDoc.Service, 2,
		"expected documentA to have 2 services after the update") {
		return
	}
	assert.Equal(t, docA.Service[1], resolvedDoc.Service[1],
		"news service of document a does not contain expected values")

	// Update document B with a new authentication key which replaces the first one:
	oldAuthKeyDocB := docB.Authentication[0].ID
	docUpdater := NutsDocUpdater{keyCreator: nutsCrypto}
	err = docUpdater.AddNewAuthenticationMethodToDIDDocument(docB)
	assert.NoError(t, err)
	err = docUpdater.RemoveVerificationMethod(oldAuthKeyDocB, docB)
	assert.NoError(t, err)
	err = vdr.Update(docB.ID, metadataDocB.Hash, *docB, nil)
	if !assert.NoError(t, err,
		"unable to update documentB with a new authenticationMethod") {
		return
	}

	// Resolve and check
	resolvedDoc, metadataDocB, err = vdr.Resolve(docB.ID, nil)
	assert.NoError(t, err,
		"expected DocumentB to be resolved without error")

	assert.Len(t, resolvedDoc.Authentication, 1)
	assert.NotEqual(t, oldAuthKeyDocB, resolvedDoc.Authentication[0].ID)

	// Check if the key has been removed from the keyStore
	key, err = nutsCrypto.GetPublicKey(oldAuthKeyDocB.String(), time.Now())
	assert.EqualError(t, err, "key not found",
		"expected authenticationKey of documentB to be removed from the keyStore")
}
