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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/structs"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	v1 "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"os"
	"path"
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
	testDirectory := io.TestWorkingDirectory(t)

	runningCtx, nodeStoppedCallback := context.WithCancel(context.Background())
	serverConfig, moduleConfig := getIntegrationTestConfig(testDirectory)
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

// Test_TLSConfiguration tests HTTP TLS termination on the Nuts node.
// - /n2n is configured to have TLS with server certificate
// - /public is configured to have TLS with server certificate, requiring a client certificate
func Test_TLSConfiguration(t *testing.T) {
	projectDir, _ := os.Getwd()
	testDirectory := io.TestWorkingDirectory(t)

	runningCtx, nodeStoppedCallback := context.WithCancel(context.Background())
	serverConfig, moduleConfig := getIntegrationTestConfig(testDirectory)
	// Configure TLS on /n2n and /metrics
	certFile := path.Join(projectDir, "test/pki/certificate-and-key.pem")
	serverConfig.TLS.CertFile = certFile
	certKeyFile := path.Join(projectDir, "test/pki/certificate-and-key.pem")
	serverConfig.TLS.CertKeyFile = certKeyFile
	trustStoreFile := path.Join(projectDir, "test/pki/truststore.pem")
	serverConfig.TLS.TrustStoreFile = trustStoreFile
	serverConfig.HTTP.AltBinds["internal"] = core.HTTPConfig{
		Address: fmt.Sprintf("localhost:%d", test.FreeTCPPort()),
		TLSMode: core.MutualTLSMode,
	}
	serverConfig.HTTP.AltBinds["metrics"] = core.HTTPConfig{
		Address: fmt.Sprintf("localhost:%d", test.FreeTCPPort()),
		TLSMode: core.TLSMode,
	}
	startCtx := startServer(testDirectory, nodeStoppedCallback, serverConfig, moduleConfig)

	// Wait for the Nuts node to start
	<-startCtx.Done()
	if !errors.Is(startCtx.Err(), context.Canceled) {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}
	defer stopNode(t, runningCtx)

	// Assert expected usage of TLS on configured interfaces
	t.Run("no TLS", func(t *testing.T) {
		assert.True(t, isHttpRunning(fmt.Sprintf("http://%s/status", serverConfig.HTTP.Address)))
	})
	t.Run("server-side TLS", func(t *testing.T) {
		tlsConfig := tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		trustStoreBytes, _ := os.ReadFile(trustStoreFile)
		_ = tlsConfig.RootCAs.AppendCertsFromPEM(trustStoreBytes)

		assert.True(t, isHttpsRunning(fmt.Sprintf("https://%s/metrics", serverConfig.HTTP.AltBinds["metrics"].Address), &tlsConfig))
	})
	t.Run("server- and client side TLS", func(t *testing.T) {
		tlsConfig := tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		trustStoreBytes, _ := os.ReadFile(trustStoreFile)
		_ = tlsConfig.RootCAs.AppendCertsFromPEM(trustStoreBytes)

		tlsConfigWithClientCert := tlsConfig.Clone()
		clientCert, _ := tls.LoadX509KeyPair(certFile, certKeyFile)
		tlsConfigWithClientCert.Certificates = []tls.Certificate{clientCert}

		target := fmt.Sprintf("https://%s/internal/network/v1/transaction", serverConfig.HTTP.AltBinds["internal"].Address)
		assert.False(t, isHttpsRunning(target, &tlsConfig))
		assert.True(t, isHttpsRunning(target, tlsConfigWithClientCert))
	})
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
	testDirectory := io.TestWorkingDirectory(t)

	// Start Nuts node
	runningCtx, nodeStoppedCallback := context.WithCancel(context.Background())
	serverConfig, moduleConfig := getIntegrationTestConfig(testDirectory)
	startCtx := startServer(testDirectory, nodeStoppedCallback, serverConfig, moduleConfig)
	<-startCtx.Done()
	if !errors.Is(startCtx.Err(), context.Canceled) {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}
	defer stopNode(t, runningCtx)

	// Create and update a DID document
	vdrClient := createVDRClient(serverConfig.HTTP.Address)
	didDocument, err := vdrClient.Create(v1.DIDCreateRequest{})
	if !assert.NoError(t, err) {
		return
	}
	_, err = vdrClient.AddNewVerificationMethod(didDocument.ID.String())
	if !assert.NoError(t, err) {
		return
	}

	// Now stop node, and start it again
	stopNode(t, runningCtx)
	runningCtx, nodeStoppedCallback = context.WithCancel(context.Background())
	// Make sure we get "fresh" ports since the OS might not immediately free closed sockets
	serverConfig, moduleConfig = getIntegrationTestConfig(testDirectory)
	startCtx = startServer(testDirectory, nodeStoppedCallback, serverConfig, moduleConfig)
	<-startCtx.Done()
	if !errors.Is(startCtx.Err(), context.Canceled) {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}

	// Assert we can read the DID document
	vdrClient = createVDRClient(serverConfig.HTTP.Address)
	doc, _, err := vdrClient.Get(didDocument.ID.String())
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, doc)
}

func createVDRClient(address string) v1.HTTPClient {
	vdrClient := v1.HTTPClient{
		ServerAddress: "http://" + address,
		Timeout:       5 * time.Second,
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
		address := fmt.Sprintf("http://%s/status", koanfInstance.String("http.default.address"))
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

func isHttpsRunning(address string, tlsConfig *tls.Config) bool {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	}}

	response, err := client.Get(address)
	if err != nil {
		println(err.Error())
		return false
	}
	_, _ = ioutil.ReadAll(response.Body)
	return response.StatusCode == http.StatusOK
}

func isHttpRunning(address string) bool {
	response, err := http.Get(address)
	if err != nil {
		println(err.Error())
		return false
	}
	_, _ = ioutil.ReadAll(response.Body)
	return response.StatusCode == http.StatusOK
}

func getIntegrationTestConfig(testDirectory string) (core.ServerConfig, ModuleConfig) {
	system := cmd.CreateSystem()
	for _, subCmd := range cmd.CreateCommand(system).Commands() {
		if subCmd.Name() == "server" {
			_ = system.Load(subCmd.Flags())
			break
		}
	}

	config := *system.Config
	config.LegacyTLS.Enabled = false

	config.Datadir = testDirectory
	config.HTTP.Address = fmt.Sprintf("localhost:%d", test.FreeTCPPort())

	networkConfig := network.DefaultConfig()
	networkConfig.GrpcAddr = fmt.Sprintf("localhost:%d", test.FreeTCPPort())

	authConfig := auth.DefaultConfig()
	authConfig.ContractValidators = []string{"dummy"} // disables IRMA

	eventsConfig := events.DefaultConfig()
	eventsConfig.Nats.Port = test.FreeTCPPort()

	return config, ModuleConfig{
		Network: networkConfig,
		Auth:    authConfig,
		Events:  eventsConfig,
	}
}

type ModuleConfig struct {
	Network network.Config `koanf:"network"`
	Auth    auth.Config    `koanf:"auth"`
	Events  events.Config  `koanf:"events"`
}
