/*
 * Copyright (C) 2022 Nuts community
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

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	httpEngine "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/pki"
	v1 "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Test_ServerLifecycle tests the lifecycle of the Nuts node:
// - It starts the Nuts node
// - Waits for the /status endpoint to return HTTP 200, indicating it started properly
// - Sends SIGINT signal
// - Waits for the main function to return
// This test was introduced because the shutdown sequence was never called, due to kill signals not being handled.
func Test_ServerLifecycle(t *testing.T) {
	testDirectory := t.TempDir()

	runningCtx, nodeStoppedCallback := context.WithCancel(context.Background())
	serverConfig, moduleConfig := getIntegrationTestConfig(t, testDirectory)
	startCtx := startServer(testDirectory, nodeStoppedCallback, serverConfig, moduleConfig)

	// Wait for the Nuts node to start
	<-startCtx.Done()

	if errors.Is(startCtx.Err(), context.Canceled) {
		t.Log("Process successfully started, sending KILL signal")
		stopNode(t, runningCtx)
	} else {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}
}

// Test_LoadExistingDAG tests the lifecycle and persistence of the DAG:
// - It starts the Nuts node
// - It creates and then updates a DID document
// - It stops and then starts the Nuts node again
// - It checks whether it can read the DID document from the DAG
// This test was introduced because we repeatedly encountered a bug where a new DAG could be created and written to,
// but (DAG) verification failed when starting the node with an existing DAG.
// It also tests that file resources (that are locked) are properly freed by the shutdown sequence,
// because it uses the same files when restarting again (without exiting the main process).
func Test_LoadExistingDAG(t *testing.T) {
	testDirectory := t.TempDir()

	// Start Nuts node
	runningCtx, nodeStoppedCallback := context.WithCancel(context.Background())
	serverConfig, moduleConfig := getIntegrationTestConfig(t, testDirectory)
	startCtx := startServer(testDirectory, nodeStoppedCallback, serverConfig, moduleConfig)
	<-startCtx.Done()
	if !errors.Is(startCtx.Err(), context.Canceled) {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}
	defer stopNode(t, runningCtx)

	// Create and update a DID document
	vdrClient := createVDRClient(moduleConfig.HTTP.Internal.Address)
	didDocument, err := vdrClient.Create(v1.DIDCreateRequest{})
	require.NoError(t, err)
	_, err = vdrClient.AddNewVerificationMethod(didDocument.ID.String())
	require.NoError(t, err)

	// Now stop node, and start it again
	stopNode(t, runningCtx)
	_, nodeStoppedCallback = context.WithCancel(context.Background())
	// Make sure we get "fresh" ports since the OS might not immediately free closed sockets
	serverConfig, moduleConfig = getIntegrationTestConfig(t, testDirectory)
	startCtx = startServer(testDirectory, nodeStoppedCallback, serverConfig, moduleConfig)
	<-startCtx.Done()
	if !errors.Is(startCtx.Err(), context.Canceled) {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}

	// Assert we can read the DID document
	vdrClient = createVDRClient(moduleConfig.HTTP.Internal.Address)
	doc, _, err := vdrClient.Get(didDocument.ID.String())
	require.NoError(t, err)
	assert.NotNil(t, doc)
}

func createVDRClient(address string) v1.HTTPClient {
	vdrClient := v1.HTTPClient{
		ClientConfig: core.ClientConfig{
			Address: "http://" + address,
			Timeout: 5 * time.Second,
		},
	}
	return vdrClient
}

func stopNode(t *testing.T, ctx context.Context) {
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	<-ctx.Done()
	t.Log("Nuts node shut down successfully.")
}

func startServer(testDirectory string, exitCallback func(), serverConfig core.ServerConfig, moduleConfig ModuleConfig) context.Context {
	// Create YAML file of server config + additional configs. Write it to disk and pass it to the server.
	koanfInstance := koanf.New(".")
	yamlParser := yaml.Parser()

	err := koanfInstance.Load(structs.ProviderWithDelim(serverConfig, "koanf", "."), nil)
	if err != nil {
		panic(err)
	}
	err = koanfInstance.Load(structs.ProviderWithDelim(moduleConfig, "koanf", "."), nil)
	if err != nil {
		panic(err)
	}

	bytes, err := koanfInstance.Marshal(yamlParser)
	if err != nil {
		panic(err)
	}

	configFile := filepath.Join(testDirectory, "config.yaml")
	err = os.WriteFile(configFile, bytes, 0644)
	if err != nil {
		panic(err)
	}

	os.Args = []string{"nuts", "server", "--configfile", configFile}
	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	go func() {
		// Wait for the Nuts node to start, until the given timeout. Check every 100ms
		interval := 100 * time.Millisecond
		attempts := int(timeout / interval)
		address := fmt.Sprintf("http://%s/status", moduleConfig.HTTP.Internal.Address)
		for i := 0; i < attempts; i++ {
			if isHttpRunning(address) {
				cancel()
				break
			}
			time.Sleep(interval)
		}
	}()

	go func() {
		main()
		exitCallback()
	}()

	return ctx
}

func isHttpRunning(address string) bool {
	response, err := http.Get(address)
	if err != nil {
		println(err.Error())
		return false
	}
	_, _ = io.ReadAll(response.Body)
	return response.StatusCode == http.StatusOK
}

func getIntegrationTestConfig(t *testing.T, testDirectory string) (core.ServerConfig, ModuleConfig) {
	system := cmd.CreateSystem(func() {
		panic("test error")
	})
	for _, subCmd := range cmd.CreateCommand(system).Commands() {
		if subCmd.Name() == "server" {
			_ = system.Load(subCmd.Flags())
			break
		}
	}

	config := *system.Config
	config.URL = "https://nuts.nl"
	config.TLS.CertFile = pki.CertificateFile(t)
	config.TLS.CertKeyFile = config.TLS.CertFile
	config.TLS.TrustStoreFile = pki.TruststoreFile(t)
	config.DIDMethods = []string{"nuts"}

	config.Datadir = testDirectory

	networkConfig := network.DefaultConfig()
	networkConfig.GrpcAddr = fmt.Sprintf("localhost:%d", test.FreeTCPPort())

	authConfig := auth.DefaultConfig()
	authConfig.ContractValidators = []string{"dummy"} // disables IRMA

	cryptoConfig := crypto.Config{Storage: "fs"}

	eventsConfig := events.DefaultConfig()
	eventsConfig.Nats.Port = test.FreeTCPPort()
	eventsConfig.Nats.Hostname = "localhost"

	httpConfig := httpEngine.DefaultConfig()
	httpConfig.Internal.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())
	httpConfig.Public.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())

	return config, ModuleConfig{
		Network: networkConfig,
		Auth:    authConfig,
		Crypto:  cryptoConfig,
		Events:  eventsConfig,
		HTTP:    httpConfig,
	}
}

type ModuleConfig struct {
	Network network.Config    `koanf:"network"`
	Auth    auth.Config       `koanf:"auth"`
	Crypto  crypto.Config     `koanf:"crypto"`
	Events  events.Config     `koanf:"events"`
	HTTP    httpEngine.Config `koanf:"http"`
}
