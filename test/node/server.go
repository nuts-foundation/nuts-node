/*
 * Copyright (C) 2023 Nuts community
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

package node

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/stretchr/testify/require"
	"net/http"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
)

const testServerConfig = `verbosity: debug
strictmode: false
network:
  enablediscovery: false
auth:
  contractvalidators:
    - dummy
  irma:
    autoupdateschemas: false
events:
  nats:
    port: 4222
`

// StartServer starts a Nuts node and returns the HTTP server URL. configFunc can be used to alter the environment before the node is started.
func StartServer(t *testing.T, configFunc ...func(internalHttpServerURL, publicHttpServerURL string)) (string, string, *core.System) {
	testDir := io.TestDirectory(t)
	system := cmd.CreateSystem(func() {})
	ctx, cancel := context.WithCancel(context.Background())

	// command line arguments
	configFile := path.Join(testDir, "nuts.yaml")
	_ = os.WriteFile(configFile, []byte(testServerConfig), os.ModePerm)
	grpcPort := fmt.Sprintf("localhost:%d", test.FreeTCPPort())
	natsPort := fmt.Sprintf("%d", test.FreeTCPPort())
	publicHttpInterface := fmt.Sprintf("localhost:%d", test.FreeTCPPort())
	internalHttpInterface := fmt.Sprintf("localhost:%d", test.FreeTCPPort())
	internalHttpServerURL := "http://" + internalHttpInterface
	publicHttpServerURL := "http://" + publicHttpInterface

	t.Setenv("NUTS_DATADIR", testDir)
	t.Setenv("NUTS_CONFIGFILE", configFile)
	t.Setenv("NUTS_HTTP_INTERNAL_ADDRESS", internalHttpInterface)
	t.Setenv("NUTS_HTTP_PUBLIC_ADDRESS", publicHttpInterface)
	t.Setenv("NUTS_NETWORK_GRPCADDR", grpcPort)
	t.Setenv("NUTS_EVENTS_NATS_PORT", natsPort)
	t.Setenv("NUTS_EVENTS_NATS_HOSTNAME", "localhost")
	t.Setenv("NUTS_URL", publicHttpServerURL)

	for _, fn := range configFunc {
		fn(internalHttpServerURL, publicHttpServerURL)
	}

	os.Args = []string{"nuts", "server"}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := cmd.Execute(ctx, system)
		if err != nil {
			panic(err)
		}
	}()

	client := tlsClient(t)
	if !test.WaitFor(t, func() (bool, error) {
		resp, err := client.Get(internalHttpServerURL + "/status")
		return err == nil && resp.StatusCode == http.StatusOK, nil
	}, time.Second*5, "Timeout while waiting for node to become available") {
		t.Fatal("time-out")
	}

	t.Cleanup(func() {
		// Signal the server to stop, then wait for the command to finish
		cancel()
		wg.Wait()
	})

	return internalHttpServerURL, publicHttpServerURL, system
}

func tlsClient(t *testing.T) http.Client {
	certFile := pki.CertificateFile(t)
	keyPair, err := tls.LoadX509KeyPair(certFile, certFile)
	require.NoError(t, err)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		RootCAs:      pki.Truststore(),
	}
	return http.Client{
		Transport: transport,
	}
}
