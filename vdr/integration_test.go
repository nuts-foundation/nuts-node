package vdr

import (
	"io/ioutil"
	"os"
	"testing"

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
	nutsConfig := core.NutsConfig{
		Verbosity: "debug",
		Datadir: tmpDir,
	}

	// Startup crypto
	nutsCrypto := &crypto.Crypto{Config: crypto.DefaultCryptoConfig()}
	nutsCrypto.Configure(nutsConfig)

	// Startup the network layer
	nutsNetwork := network.NewNetworkInstance(network.DefaultConfig(), nutsCrypto)
	nutsNetwork.Configure(nutsConfig)
	nutsNetwork.Start()

	// Init the VDR
	vdr := NewVDR(DefaultConfig(), nutsCrypto, nutsNetwork)
	vdr.Start()

	// Start with a first and fresh document
	didDoc, err := vdr.Create()
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, didDoc)

	// Check if the document can be found in the store
	resolvedDoc, metadata, err := vdr.Resolve(didDoc.ID, nil)

	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, resolvedDoc)
	assert.NotNil(t, metadata)
	assert.Equal(t, didDoc.ID, resolvedDoc.ID)
}
