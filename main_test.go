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
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	v1 "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"os"
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
	testDirectory := io.TestDirectory(t)

	runningCtx, nodeStoppedCallback := context.WithCancel(context.Background())
	startCtx := startServer(test.GetIntegrationTestConfig(testDirectory), nodeStoppedCallback)

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
	testDirectory := io.TestDirectory(t)

	opts := test.GetIntegrationTestConfig(testDirectory)

	// Start Nuts node
	runningCtx, nodeStoppedCallback := context.WithCancel(context.Background())
	startCtx := startServer(opts, nodeStoppedCallback)
	<-startCtx.Done()
	if !errors.Is(startCtx.Err(), context.Canceled) {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}
	defer stopNode(t, runningCtx)

	// Create and update a DID document
	vdrClient := createVDRClient(opts)
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
	opts = test.GetIntegrationTestConfig(testDirectory)
	startCtx = startServer(opts, nodeStoppedCallback)
	<-startCtx.Done()
	if !errors.Is(startCtx.Err(), context.Canceled) {
		t.Fatalf("Process didn't start before the time-out expired: %v", startCtx.Err())
	}

	// Assert we can read the DID document
	vdrClient = createVDRClient(opts)
	doc, _, err := vdrClient.Get(didDocument.ID.String())
	if !assert.NoError(t, err) {
		return
	}
	assert.NotNil(t, doc)
}

func createVDRClient(opts map[string]string) v1.HTTPClient {
	vdrClient := v1.HTTPClient{
		ServerAddress: "http://" + opts["http.default.address"],
		Timeout:       5 * time.Second,
	}
	return vdrClient
}

func stopNode(t *testing.T, ctx context.Context) {
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	<-ctx.Done()
	t.Log("Nuts node shut down successfully.")
}

func startServer(opts map[string]string, exitCallback func()) context.Context {
	// Collect options
	var optsSlice []string
	for key, value := range opts {
		optsSlice = append(optsSlice, "--"+key+"="+fmt.Sprintf("%s", value))
	}

	os.Args = append([]string{"nuts", "server"}, optsSlice...)
	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	go func() {
		// Wait for the Nuts node to start, until the given timeout. Check every 100ms
		interval := 100 * time.Millisecond
		attempts := int(timeout / interval)
		address := fmt.Sprintf("http://%s/status", opts["http.default.address"])
		for i := 0; i < attempts; i++ {
			if isRunning(address) {
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

func isRunning(address string) bool {
	response, err := http.Get(address)
	if err != nil {
		println(err.Error())
		return false
	}
	_, _ = ioutil.ReadAll(response.Body)
	return response.StatusCode == http.StatusOK
}
