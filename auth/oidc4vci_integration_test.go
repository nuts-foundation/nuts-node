package auth

import (
	"context"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0"
	"github.com/nuts-foundation/nuts-node/auth/oidc4vci"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/stretchr/testify/require"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestOIDC4VCIHappyFlow tests issuing a VC using OIDC4VCI.
// Steps:
//   - Create Echo server, register OIDC4VCI API
//   - Issue a VC using the OIDC4VCI Credential Issuer, check that it is received by the wallet
//   - Check that the VC is stored in the wallet
func TestOIDC4VCIHappyFlow(t *testing.T) {
	// Create issuer and wallet
	ctrl := gomock.NewController(t)
	credentialStore := vcr.NewMockWriter(ctrl)
	issuer := oidc4vci.NewIssuer()
	api := &oidc4vci_v0.Wrapper{
		Issuer:          issuer,
		CredentialStore: credentialStore,
	}

	// Start HTTP server
	httpPort := test.FreeTCPPort()
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
	walletURL := fmt.Sprintf("http://localhost:%d", httpPort)
	test.WaitFor(t, func() (bool, error) {
		// Check if Start() error-ed
		if len(startErrorChannel) > 0 {
			return false, <-startErrorChannel
		}
		_, err := http.Get(walletURL)
		return err == nil, nil
	}, 5*time.Second, "time-out waiting for HTTP server to start")

	issuerDID := did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")
	credentialID, _ := ssi.ParseURI(issuerDID.String() + "#1")
	receiverDID := did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")

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
		IssuanceDate: time.Now(),
		CredentialSubject: []interface{}{map[string]interface{}{
			"ID": receiverDID.String(),
		}},
	}

	credentialStore.EXPECT().StoreCredential(credential, nil).Return(nil)

	// Now issue the VC
	err := issuer.Offer(context.Background(), credential, walletURL)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)
}
