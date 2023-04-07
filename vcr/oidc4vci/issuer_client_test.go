package oidc4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func Test_httpIssuerClient_New(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	t.Run("empty identifier", func(t *testing.T) {
		client, err := NewIssuerClient(ctx, httpClient, "")

		require.EqualError(t, err, "empty Credential Issuer Identifier")
		require.Nil(t, client)
	})
	t.Run("error loading credential issuer metadata", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.issuerMetadataHandler = func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
		}

		client, err := NewIssuerClient(ctx, httpClient, setup.providerMetadata.Issuer)

		require.ErrorContains(t, err, "unable to load Credential Issuer Metadata")
		require.Nil(t, client)
	})
	t.Run("error loading provider metadata", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.providerMetadataHandler = func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
		}

		client, err := NewIssuerClient(ctx, httpClient, setup.providerMetadata.Issuer)

		require.ErrorContains(t, err, "unable to load OIDC Provider Metadata")
		require.Nil(t, client)
	})
}

func Test_httpIssuerClient_GetCredential(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{}
	credentialRequest := CredentialRequest{
		CredentialDefinition: &map[string]interface{}{
			"issuer": "issuer",
		},
		Format: "ldp_vc",
	}
	t.Run("ok", func(t *testing.T) {
		setup := setupClientTest(t)
		client, err := NewIssuerClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.GetCredential(ctx, credentialRequest, "token")

		require.NoError(t, err)
		require.NotNil(t, credential)
	})
	t.Run("error - no credentials in response", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.credentialHandler = HTTPPostHandler(CredentialResponse{})
		client, err := NewIssuerClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.GetCredential(ctx, credentialRequest, "token")

		require.EqualError(t, err, "credential response does not contain a credential")
		require.Nil(t, credential)
	})
	t.Run("error - invalid credentials in response", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.credentialHandler = HTTPPostHandler(CredentialResponse{Credential: &map[string]interface{}{
			"issuer": []string{"1", "2"}, // Invalid issuer
		}})
		client, err := NewIssuerClient(ctx, httpClient, setup.issuerMetadata.CredentialIssuer)
		require.NoError(t, err)

		credential, err := client.GetCredential(ctx, credentialRequest, "token")

		require.ErrorContains(t, err, "unable to unmarshal received credential: json: cannot unmarshal")
		require.Nil(t, credential)
	})
}

func setupClientTest(t *testing.T) *issuerClientTest {
	issuerMD := new(CredentialIssuerMetadata)
	oidcProvider := new(ProviderMetadata)
	credentialResponse := CredentialResponse{
		Format: "ldp_vc",
		Credential: &map[string]interface{}{
			"@context":          []string{"https://www.w3.org/2018/credentials/v1"},
			"type":              []string{"VerifiableCredential"},
			"issuer":            "issuer",
			"issuanceDate":      time.Now().Format(time.RFC3339),
			"credentialSubject": map[string]interface{}{"id": "id"},
		},
	}
	clientTest := &issuerClientTest{
		issuerMetadataHandler:   HTTPGetHandler(issuerMD),
		providerMetadataHandler: HTTPGetHandler(oidcProvider),
		credentialHandler:       HTTPPostHandler(credentialResponse),
		issuerMetadata:          issuerMD,
		providerMetadata:        oidcProvider,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/issuer"+CredentialIssuerMetadataWellKnownPath, func(writer http.ResponseWriter, request *http.Request) {
		clientTest.issuerMetadataHandler(writer, request)
	})
	mux.HandleFunc("/issuer"+ProviderMetadataWellKnownPath, func(writer http.ResponseWriter, request *http.Request) {
		clientTest.providerMetadataHandler(writer, request)
	})
	mux.HandleFunc("/issuer/credential", func(writer http.ResponseWriter, request *http.Request) {
		clientTest.credentialHandler(writer, request)
	})
	serverURL := startHTTPServer(t, mux)

	issuerIdentifier := serverURL + "/issuer"
	issuerMD.CredentialIssuer = issuerIdentifier
	issuerMD.CredentialEndpoint = issuerIdentifier + "/credential"
	oidcProvider.Issuer = issuerIdentifier
	oidcProvider.TokenEndpoint = issuerIdentifier + "/token"
	return clientTest
}

func HTTPPostHandler(response interface{}) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if request.Method != "POST" {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		data, _ := json.Marshal(response)
		writer.WriteHeader(http.StatusOK)
		writer.Write(data)
	}
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

type issuerClientTest struct {
	issuerMetadata          *CredentialIssuerMetadata
	providerMetadata        *ProviderMetadata
	issuerMetadataHandler   http.HandlerFunc
	providerMetadataHandler http.HandlerFunc
	credentialHandler       http.HandlerFunc
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
