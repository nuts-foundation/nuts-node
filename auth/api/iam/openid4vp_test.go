package iam

import (
	"bytes"
	"context"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/url"
	"testing"
)

var holderDID = did.MustParseDID("did:web:example.com:holder")
var issuerDID = did.MustParseDID("did:web:example.com:issuer")

func TestWrapper_sendPresentationRequest(t *testing.T) {
	instance := New(nil, nil, nil)

	redirectURI, _ := url.Parse("https://example.com/redirect")
	verifierID, _ := url.Parse("https://example.com/verifier")
	walletID, _ := url.Parse("https://example.com/wallet")

	httpResponse := &stubResponseWriter{}

	err := instance.sendPresentationRequest(context.Background(), httpResponse, "test-scope", *redirectURI, *verifierID, *walletID)

	require.NoError(t, err)
	require.Equal(t, http.StatusFound, httpResponse.statusCode)
	location := httpResponse.headers.Get("Location")
	require.NotEmpty(t, location)
	locationURL, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, "https", locationURL.Scheme)
	assert.Equal(t, "example.com", locationURL.Host)
	assert.Equal(t, "/wallet/authorize", locationURL.Path)
	assert.Equal(t, "test-scope", locationURL.Query().Get("scope"))
	assert.Equal(t, "vp_token id_token", locationURL.Query().Get("response_type"))
	assert.Equal(t, "direct_post", locationURL.Query().Get("response_mode"))
	assert.Equal(t, "https://example.com/verifier/.well-known/openid-wallet-metadata/metadata.xml", locationURL.Query().Get("client_metadata_uri"))
}

func TestWrapper_handlePresentationRequest(t *testing.T) {
	credentialID, _ := ssi.ParseURI("did:web:example.com:issuer#6AF53584-3337-4766-8C8D-0BFD54F6E527")
	walletCredentials := []vc.VerifiableCredential{
		{
			Context: []ssi.URI{
				vc.VCContextV1URI(),
				credential.NutsV1ContextURI,
			},
			ID:     credentialID,
			Issuer: issuerDID.URI(),
			Type:   []ssi.URI{vc.VerifiableCredentialTypeV1URI(), *credential.NutsOrganizationCredentialTypeURI},
			CredentialSubject: []interface{}{
				map[string]interface{}{
					"id": holderDID.URI(),
					"organization": map[string]interface{}{
						"name": "Test Organization",
						"city": "Test City",
					},
				},
			},
		},
	}
	t.Run("with scope", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockVDR := types.NewMockVDR(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		instance := New(nil, mockVCR, mockVDR)
		mockVCR.EXPECT().Search(gomock.Any(), gomock.Any(), false, nil).Return(walletCredentials, nil)
		mockVDR.EXPECT().IsOwner(gomock.Any(), holderDID).Return(true, nil)

		params := map[string]string{
			"scope":               "eOverdracht-overdrachtsbericht",
			"response_type":       "code",
			"response_mode":       "direct_post",
			"client_metadata_uri": "https://example.com/client_metadata.xml",
		}

		response, err := instance.handlePresentationRequest(params, createSession(params, holderDID))

		require.NoError(t, err)
		httpResponse := &stubResponseWriter{}
		_ = response.VisitHandleAuthorizeRequestResponse(httpResponse)
		require.Equal(t, http.StatusOK, httpResponse.statusCode)
		assert.Contains(t, httpResponse.body.String(), "</html>")
	})
}

type stubResponseWriter struct {
	headers    http.Header
	body       *bytes.Buffer
	statusCode int
}

func (s *stubResponseWriter) Header() http.Header {
	if s.headers == nil {
		s.headers = make(http.Header)
	}
	return s.headers

}

func (s *stubResponseWriter) Write(i []byte) (int, error) {
	if s.body == nil {
		s.body = new(bytes.Buffer)
	}
	return s.body.Write(i)
}

func (s *stubResponseWriter) WriteHeader(statusCode int) {
	s.statusCode = statusCode
}
