package oidc4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func Test_httpIssuerClient_GetCredential(t *testing.T) {
	issuerMD := new(types.CredentialIssuerMetadata)
	oidcProvider := new(types.OIDCProviderMetadata)
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/issuer/.well-known/openid-credential-issuer", HTTPGetHandler(issuerMD))
	mux.HandleFunc("/issuer/.well-known/openid-configuration", HTTPGetHandler(oidcProvider))
	serverURL := startHTTPServer(t, mux)

	issuerIdentifier := serverURL + "/issuer"
	issuerMD.CredentialIssuer = issuerIdentifier
	issuerMD.CredentialEndpoint = issuerIdentifier + "/credential"
	oidcProvider.Issuer = issuerIdentifier
	oidcProvider.TokenEndpoint = issuerIdentifier + "/token"

	client, err := NewIssuerClient(ctx, &http.Client{}, issuerIdentifier)
	require.NoError(t, err)

	credential, err := client.GetCredential(ctx, types.CredentialRequest{
		CredentialDefinition: &map[string]interface{}{
			"issuer": "issuer",
		},
		Format: "ldp_vc",
	}, "token")

	require.NoError(t, err)
	require.NotNil(t, credential)
}

func HTTPGetHandler(response interface{}) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if request.Method != "GET" {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		data, _ := json.Marshal(response)
		writer.WriteHeader(http.StatusOK)
		writer.Write(data)
	}
}

func startHTTPServer(t *testing.T, mux *http.ServeMux) string {
	httpPort := test.FreeTCPPort()
	server := &http.Server{Addr: fmt.Sprintf(":%d", httpPort), Handler: mux}
	httpServerURL := fmt.Sprintf("http://localhost:%d", httpPort)
	startErrorChannel := make(chan error)
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			startErrorChannel <- err
		}
	}()
	test.WaitFor(t, func() (bool, error) {
		// Check if Start() error-ed
		if len(startErrorChannel) > 0 {
			return false, <-startErrorChannel
		}
		_, err := http.Get(httpServerURL)
		return err == nil, nil
	}, 5*time.Second, "time-out waiting for HTTP server to start")
	t.Cleanup(func() {
		server.Shutdown(context.Background())
	})
	return httpServerURL
}
