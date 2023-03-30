package test

import (
	"context"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/stretchr/testify/require"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestOIDC4VCIHappyFlow tests issuing a VC using OIDC4VCI.
// Steps:
//   - Create Echo server, register OIDC4VCI API
//   - Issue a VC using the OIDC4VCI Credential Issuer, check that it is received by the wallet
//   - Check that the VC is stored in the wallet
func TestOIDC4VCIHappyFlow(t *testing.T) {
	issuerDID := did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")
	receiverDID := did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")

	httpPort := test.FreeTCPPort()
	httpServerURL := fmt.Sprintf("http://localhost:%d", httpPort)
	//issuerID := httpServerURL + "/identity/" + issuerDID.String()
	//receiverID := httpServerURL + "/identity/" + receiverDID.String()

	// Create issuer and wallet
	ctrl := gomock.NewController(t)
	credentialStore := vcr.NewMockWriter(ctrl)
	issuerRegistry := oidc4vci.NewIssuerRegistry(httpServerURL + "/identity/")
	holderRegistry := oidc4vci.NewHolderRegistry(httpServerURL+"/identity/", credentialStore)
	api := &oidc4vci_v0.Wrapper{
		IssuerRegistry: issuerRegistry,
		HolderRegistry: holderRegistry,
	}

	// Start HTTP server
	httpServer := echo.New()
	httpServer.Use(middleware.Logger())
	defer httpServer.Close()
	api.Routes(httpServer)
	startErrorChannel := make(chan error)
	go func() {
		err := httpServer.Start(":" + strconv.Itoa(httpPort))
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

	credentialID, _ := ssi.ParseURI(issuerDID.String() + "#1")

	credential := vc.VerifiableCredential{
		Context: []ssi.URI{
			didservice.JWS2020ContextV1URI(),
			didservice.NutsDIDContextV1URI(),
		},
		ID: credentialID,
		Type: []ssi.URI{
			ssi.MustParseURI("VerifiableCredential"),
			ssi.MustParseURI("NutsAuthorizationCredential"),
		},
		Issuer:       issuerDID.URI(),
		IssuanceDate: time.Now().Truncate(time.Second),
		CredentialSubject: []interface{}{map[string]interface{}{
			"ID": receiverDID.String(),
		}},
	}

	vcStored := atomic.Pointer[bool]{}
	credentialStore.EXPECT().StoreCredential(credential, nil).DoAndReturn(func(_ vc.VerifiableCredential, _ *time.Time) error {
		vcStored.Store(new(bool))
		return nil
	})

	// Now issue the VC
	err := issuerRegistry.Get(issuerDID.String()).Offer(context.Background(), credential, httpServerURL)
	require.NoError(t, err)

	test.WaitFor(t, func() (bool, error) {
		return vcStored.Load() != nil, nil
	}, 5*time.Second, "time-out waiting for VC to be stored")
}
