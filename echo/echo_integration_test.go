/*
 * Nuts node
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

package echo

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/cmd"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

// TestStatusCodes tests if the returned errors from the API implementations are correctly translated to status codes
func TestStatusCodes(t *testing.T) {
	httpPort := startServer(t)
	defer resetEnv()

	baseUrl := fmt.Sprintf("http://localhost%s", httpPort)

	t.Run("404s", func(t *testing.T) {
		urls := []string{
			"/internal/auth/v1/signature/session/1",
			"/public/auth/v1/contract/1",
			"/internal/didman/v1/did/did:nuts:1/compoundservice",
			"/internal/didman/v1/did/did:nuts:1/compoundservice/1/endpoint/2",
			"/internal/network/v1/transaction/0000000000000000000000000000000000000000000000000000000000000000",
			"/internal/network/v1/transaction/0000000000000000000000000000000000000000000000000000000000000000/payload",
			"/internal/vcr/v2/vc/1",
			"/internal/vdr/v1/did/did:nuts:1",
		}

		for _, url := range urls {
			resp, err := http.Get(fmt.Sprintf("%s%s", baseUrl, url))

			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		}
	})
}

func startServer(t *testing.T) string {
	testDir := io.TestDirectory(t)
	system := cmd.CreateSystem()
	ctx, cancel := context.WithCancel(context.Background())

	// command line arguments
	configFile := path.Join(".", "nuts.yaml")
	grpcPort := fmt.Sprintf(":%d", test.FreeTCPPort())
	natsPort := fmt.Sprintf("%d", test.FreeTCPPort())
	httpPort := fmt.Sprintf(":%d", test.FreeTCPPort())

	os.Setenv("NUTS_DATADIR", testDir)
	os.Setenv("NUTS_CONFIGFILE", configFile)
	os.Setenv("NUTS_HTTP_DEFAULT_ADDRESS", httpPort)
	os.Setenv("NUTS_NETWORK_GRPCADDR", grpcPort)
	os.Setenv("NUTS_EVENTS_NATS_PORT", natsPort)
	os.Args = []string{"nuts", "server"}

	go func() {
		err := cmd.Execute(ctx, system)
		if err != nil {
			panic(err)
		}
	}()

	if !test.WaitFor(t, func() (bool, error) {
		resp, err := http.Get(fmt.Sprintf("http://localhost%s/status", httpPort))
		return err == nil && resp.StatusCode == http.StatusOK, nil
	}, time.Second * 5, "Timeout while waiting for node to become available") {
		t.Fatal("time-out")
	}

	t.Cleanup(func() {
		cancel()

		// wait for port to become free again
		test.WaitFor(t, func() (bool, error) {
			if a, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("localhost%s", httpPort)); err == nil {
				if l, err := net.ListenTCP("tcp", a); err == nil {
					l.Close()
					return true, nil
				}
			}

			return false, nil
		}, 5*time.Second, "Timeout while waiting for node to shutdown")
	})

	return httpPort
}

func resetEnv() {
	os.Unsetenv("NUTS_CONFIGFILE")
	os.Unsetenv("NUTS_DATADIR")
	os.Unsetenv("NUTS_HTTP_DEFAULT_ADDRESS")
	os.Unsetenv("NUTS_NETWORK_GRPCADDR")
	os.Unsetenv("NUTS_EVENTS_NATS_PORT")
}
