package issuer

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

var issuerDID = did.MustParseDID("did:nuts:issuer")
var holderDID = did.MustParseDID("did:nuts:holder")
var issuedVC = vc.VerifiableCredential{
	Issuer: issuerDID.URI(),
	CredentialSubject: []interface{}{
		map[string]interface{}{
			"id": holderDID.String(),
		},
	},
}

func Test_memoryIssuer_Metadata(t *testing.T) {
	metadata, err := NewOIDCIssuer("https://example.com").Metadata(issuerDID)

	require.NoError(t, err)
	assert.Equal(t, oidc4vci.CredentialIssuerMetadata{
		CredentialIssuer:     "https://example.com/did:nuts:issuer",
		CredentialEndpoint:   "https://example.com/did:nuts:issuer/issuer/oidc4vci/credential",
		CredentialsSupported: []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}},
	}, metadata)
}

func Test_memoryIssuer_ProviderMetadata(t *testing.T) {
	metadata, err := NewOIDCIssuer("https://example.com").ProviderMetadata(issuerDID)

	require.NoError(t, err)
	assert.Equal(t, oidc4vci.ProviderMetadata{
		Issuer:        "https://example.com/did:nuts:issuer",
		TokenEndpoint: "https://example.com/did:nuts:issuer/oidc/token",
	}, metadata)
}

func Test_memoryIssuer_HandleCredentialRequest(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		issuer := NewOIDCIssuer("https://example.com").(*memoryIssuer)
		issuer.createOffer(issuedVC, "secret")
		issuer.accessTokens["access-token"] = "secret"

		auditLogs := audit.CaptureLogs(t)
		response, err := issuer.HandleCredentialRequest(audit.TestContext(), issuerDID, "access-token")

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, issuerDID.URI(), response.Issuer)
		auditLogs.AssertContains(t, "VCR", "VerifiableCredentialRetrievedEvent", audit.TestActor, "VC retrieved by wallet over OIDC4VCI")
	})
	t.Run("unknown access token", func(t *testing.T) {
		issuer := NewOIDCIssuer("https://example.com")

		auditLogs := audit.CaptureLogs(t)
		response, err := issuer.HandleCredentialRequest(audit.TestContext(), issuerDID, "access-token")

		assert.EqualError(t, err, "invalid access token")
		assert.Nil(t, response)
		auditLogs.AssertContains(t, "VCR", "InvalidOAuthToken", audit.TestActor, "Client tried retrieving credential over OIDC4VCI with unknown OAuth2 access token")
	})
}

func Test_memoryIssuer_OfferCredential(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := oidc4vci.NewMockWalletAPIClient(ctrl)
		wallet.EXPECT().OfferCredential(gomock.Any(), gomock.Any()).Return(nil)
		walletClientCreator = func(_ context.Context, _ *http.Client, _ string) (oidc4vci.WalletAPIClient, error) {
			return wallet, nil
		}
		issuer := NewOIDCIssuer("https://example.com").(*memoryIssuer)

		err := issuer.OfferCredential(audit.TestContext(), issuedVC, "access-token")

		require.NoError(t, err)
	})
	t.Run("client offer error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		wallet := oidc4vci.NewMockWalletAPIClient(ctrl)
		wallet.EXPECT().Metadata().Return(oidc4vci.OAuth2ClientMetadata{CredentialOfferEndpoint: "here-please"})
		wallet.EXPECT().OfferCredential(gomock.Any(), gomock.Any()).Return(errors.New("failed"))
		walletClientCreator = func(_ context.Context, _ *http.Client, _ string) (oidc4vci.WalletAPIClient, error) {
			return wallet, nil
		}
		issuer := NewOIDCIssuer("https://example.com").(*memoryIssuer)

		err := issuer.OfferCredential(audit.TestContext(), issuedVC, "access-token")

		require.EqualError(t, err, "unable to offer credential (client-metadata-url=here-please): failed")
	})
}

func Test_memoryIssuer_HandleAccessTokenRequest(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		issuer := NewOIDCIssuer("https://example.com").(*memoryIssuer)
		_ = issuer.createOffer(issuedVC, "code")

		accessToken, err := issuer.HandleAccessTokenRequest(audit.TestContext(), issuerDID, "code")

		require.NoError(t, err)
		assert.NotEmpty(t, accessToken)
	})
	t.Run("unknown pre-authorized code", func(t *testing.T) {
		issuer := NewOIDCIssuer("https://example.com").(*memoryIssuer)
		_ = issuer.createOffer(issuedVC, "some-other-code")

		auditLog := audit.CaptureLogs(t)
		accessToken, err := issuer.HandleAccessTokenRequest(audit.TestContext(), issuerDID, "code")

		assert.EqualError(t, err, "unknown pre-authorized code")
		assert.Empty(t, accessToken)
		auditLog.AssertContains(t, "VCR", "InvalidOAuthToken", audit.TestActor, "Client tried requesting access token (for OIDC4VCI) with unknown OAuth2 pre-authorized code")
	})
}
