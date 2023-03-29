package auth

import (
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0"
	"github.com/nuts-foundation/nuts-node/auth/oidc4vci"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/stretchr/testify/require"
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
	api := &oidc4vci_v0.Wrapper{
		Issuer:          oidc4vci.NewIssuer(),
		CredentialStore: credentialStore,
	}

	// Start HTTP server
	httpServer := echo.New()
	api.Routes(httpServer)
	err := httpServer.Start(":0")
	require.NoError(t, err)
	defer httpServer.Close()
	
	jsonld.TestCredential
	credential := vc.VerifiableCredential{
		Context:           nil,
		ID:                nil,
		Type:              nil,
		Issuer:            ssi.URI{},
		IssuanceDate:      time.Time{},
		ExpirationDate:    nil,
		CredentialStatus:  nil,
		CredentialSubject: nil,
		Proof:             nil,
	}

	credentialStore.EXPECT().Write(gomock.Any()).Do(func(credential vcr.VerifiableCredential) {
}
