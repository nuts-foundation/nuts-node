package vdr

import (
	"io/ioutil"
	"net/url"
	"os"
	"testing"

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
	resolvedDoc, metadata, err := vdr.Resolve(docA.ID, nil)

	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, resolvedDoc)
	assert.NotNil(t, metadata)
	assert.Equal(t, docA.ID, resolvedDoc.ID)

	serviceID, _ := url.Parse(docA.ID.String() + "#service-1")

	// Try to update the document with a service
	docA.Service = append(docA.Service, did.Service{
		ID:              did.URI{URL: *serviceID},
		Type:            "service",
		ServiceEndpoint: []interface{}{"http://example.com/service"},
	})

	err = vdr.Update(docA.ID, metadata.Hash, *docA, nil)
	if !assert.NoError(t, err, "unable to update docA with a new service") {
		return
	}


	resolvedDoc, metadata, err = vdr.Resolve(docA.ID, nil)
	if !assert.NoError(t, err, "unable to resolve updated document"){
		return
	}

	assert.Equal(t, docA.Service[0], resolvedDoc.Service[0], "expected updated docA to have a service")

	// Create a new DID Document named DocumentB
	docB, err := vdr.Create()
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, docB)

	// Update documentA with documentB as its new Controller
	docA.Controller = []did.DID{docB.ID}
	err = vdr.Update(docA.ID, metadata.Hash, *docA, nil)
	if !assert.NoError(t, err, "unable to update docA with a new controller") {
		return
	}

	resolvedDoc, metadata, err = vdr.Resolve(docA.ID, nil)
	if !assert.NoError(t, err, "unable to resolve updated document A"){
		return
	}

	assert.Equal(t, []did.DID{docB.ID}, resolvedDoc.Controller, "expected updated docA to have document B as its controller")

	// Update and check DocumentA with a new service:
	serviceID, _ = url.Parse(docA.ID.String() + "#service-2")
	docA.Service = append(docA.Service, did.Service{
		ID:              did.URI{URL: *serviceID},
		Type:            "service-2",
		ServiceEndpoint: []interface{}{"http://example.com/service2"},
	})
	err = vdr.Update(docA.ID, metadata.Hash, *docA, nil)
	if !assert.NoError(t, err, "unable to update docA with a new service") {
		return
	}
	resolvedDoc, metadata, err = vdr.Resolve(docA.ID, nil)
	if !assert.NoError(t, err, "unable to resolve updated document A"){
		return
	}

	if !assert.Len(t, resolvedDoc.Service, 2, "expected document A to have 2 services after the update") {
		return
	}
	assert.Equal(t, docA.Service[1], resolvedDoc.Service[1], "news service of document a does not contain expected values")
}
