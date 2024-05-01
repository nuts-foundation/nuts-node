/*
 * Nuts node
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
 */

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage/fs"
	testIo "github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewCryptoEngine_FlagSet(t *testing.T) {
	t.Run("Cobra help should list flags", func(t *testing.T) {
		cmd := newRootCommand()
		cmd.Flags().AddFlagSet(FlagSet())
		cmd.SetArgs([]string{"--help"})

		buf := new(bytes.Buffer)
		cmd.SetOut(buf)

		_, err := cmd.ExecuteC()

		if err != nil {
			t.Errorf("Expected no error, got %s", err.Error())
		}

		result := buf.String()

		if !strings.Contains(result, "--crypto.storage") {
			t.Errorf("Expected --storage to be command line flag")
		}

	})
}

func newRootCommand() *cobra.Command {
	testRootCommand := &cobra.Command{
		Use: "root",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}

	return testRootCommand
}

func Test_fs2VaultCommand(t *testing.T) {
	// WithParam up webserver that stubs Vault
	importRequests := make(map[string]string, 0)
	s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "BEGIN PRIVATE KEY") {
			importRequests[request.RequestURI] = string(data)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("{\"request_id\":\"d728876e-ea1e-8a58-f297-dcd4cd0a41bb\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":{\"keys\":[\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#45KSfeG71ZMh9NjGzSWFfcMsmu5587J93prf8Io1wf4\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#6Cc91cQQze7txdcEor_zkM4YSwX0kH1wsiMyeV9nedA\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#MaNou-G07aPD7oheretmI2C_VElG1XaHiqh89SlfkWQ\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#alt3OIpy21VxDlWao0jRumIyXi3qHBPG-ir5q8zdv8w\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#wumme98rwUOQVle-sT_MP3pRg_oqblvlanv3zYR2scc\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#yBLHNjVq_WM3qzsRQ_zi2yOcedjY9FfVfByp3HgEbR8\",\"did:nuts:8AB7Jf8KYgNHC52sfyTTK2f2yGnDoSHkgzDgeqvrUBLo#yREqK5id7I6SP1Iq7teThin2o53w17tb9sgEXZBIcDo\"]},\"wrap_info\":null,\"warnings\":null,\"auth\":null}"))
	}))
	defer s.Close()

	// Configure target
	t.Setenv("NUTS_CRYPTO_STORAGE", "vaultkv")
	t.Setenv("NUTS_CRYPTO_VAULT_ADDRESS", s.URL)

	testDirectory := testIo.TestDirectory(t)
	setupFSStoreData(t, testDirectory)

	outBuf := new(bytes.Buffer)
	cryptoCmd := ServerCmd()
	for _, cmd := range cryptoCmd.Commands() {
		cmd.Flags().AddFlagSet(core.FlagSet())
		cmd.Flags().AddFlagSet(FlagSet())
	}
	cryptoCmd.SetOut(outBuf)
	cryptoCmd.SetArgs([]string{"fs2vault", testDirectory})

	err := cryptoCmd.Execute()
	require.NoError(t, err)

	// Assert all keys were imported into Vault on the expected paths
	assert.Len(t, importRequests, 3)
	assert.NotNil(t, importRequests["/v1/kv/nuts-private-keys/pk1"])
	assert.NotNil(t, importRequests["/v1/kv/nuts-private-keys/pk2"])
	assert.NotNil(t, importRequests["/v1/kv/nuts-private-keys/pk3"])

	// Assert imported keys are logged
	output := outBuf.String()
	assert.Contains(t, output, "pk1")
	assert.Contains(t, output, "pk2")
	assert.Contains(t, output, "pk3")
}

func Test_fs2ExternalStore(t *testing.T) {
	// tests imports 1 new key, skips a known one, and the server returns an error for the third one
	t.Run("ok", func(t *testing.T) {
		// WithParam up webserver that stubs Vault
		importRequests := make(map[string]string, 0)

		s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			data, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			importRequests[request.RequestURI] = string(data)
			switch request.RequestURI {
			case "/secrets/pk1":
				writer.WriteHeader(http.StatusOK)
			case "/secrets/pk2":
				writer.WriteHeader(http.StatusConflict)
			case "/secrets/pk3":
				writer.WriteHeader(http.StatusBadRequest)
			}

		}))
		defer s.Close()

		// Configure target
		t.Setenv("NUTS_CRYPTO_STORAGE", "external")
		t.Setenv("NUTS_CRYPTO_EXTERNAL_ADDRESS", s.URL)

		testDirectory := testIo.TestDirectory(t)
		setupFSStoreData(t, testDirectory)

		outBuf := new(bytes.Buffer)
		cryptoCmd := ServerCmd()
		for _, cmd := range cryptoCmd.Commands() {
			cmd.Flags().AddFlagSet(core.FlagSet())
			cmd.Flags().AddFlagSet(FlagSet())
		}
		cryptoCmd.SetOut(outBuf)
		cryptoCmd.SetArgs([]string{"fs2external", testDirectory})

		err := cryptoCmd.Execute()
		require.EqualError(t, err, "unable to store private key in Vault (kid=pk3): unable to save private key: server returned HTTP 400")

		// Assert 2 keys were imported into Vault on the expected paths
		assert.Len(t, importRequests, 3)
		assert.Contains(t, importRequests, "/secrets/pk1")
		assert.Contains(t, importRequests, "/secrets/pk2")
		assert.Contains(t, importRequests, "/secrets/pk3")

		// Assert imported keys are logged
		output := outBuf.String()
		assert.Contains(t, output, "pk1")
		// key 2 is skipped because it already exists
		assert.NotContains(t, output, "pk2")
		// key 3 caused an error
		assert.Contains(t, output, "Failed to import all fs keys into external store: unable to store private key in Vault (kid=pk3)")
	})
}

// setupFSStoreData creates a directory with 2 keys in it
// Can be used to test the fs2* commands
func setupFSStoreData(t *testing.T, testDirectory string) {
	t.Helper()
	ctx := context.Background()

	// WithParam up crypto filesystem with some keys
	pk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk3, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fs, _ := fs.NewFileSystemBackend(testDirectory)
	_ = fs.SavePrivateKey(ctx, "pk1", pk1)
	_ = fs.SavePrivateKey(ctx, "pk2", pk2)
	_ = fs.SavePrivateKey(ctx, "pk3", pk3)
}
