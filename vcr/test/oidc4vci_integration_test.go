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

package test

import (
	"context"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/test"
	httptest "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/require"
	"sync/atomic"
	"testing"
	"time"
)

var issuerDID = did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")
var receiverDID = did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")
var credentialID = ssi.MustParseURI(issuerDID.String() + "#1")
var credential = vc.VerifiableCredential{
	Context: []ssi.URI{
		didservice.JWS2020ContextV1URI(),
		didservice.NutsDIDContextV1URI(),
	},
	ID: &credentialID,
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

// TestOIDC4VCIHappyFlow tests issuing a VC using OIDC4VCI.
// Steps:
//   - Create Echo server, register OIDC4VCI API
//   - Issue a VC using the OIDC4VCI Credential Issuer, check that it is received by the wallet
//   - Check that the VC is stored in the wallet
func TestOIDC4VCIHappyFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockVCR := vcr.NewMockVCR(ctrl)
	api := &oidc4vci_v0.Wrapper{
		VCR: mockVCR,
	}
	httpServerURL := httptest.StartEchoServer(t, api.Routes)

	// Create issuer and wallet
	receiverIdentifier := httpServerURL + "/identity/" + receiverDID.String()
	receiverMetadataURL := receiverIdentifier + "/.well-known/openid-credential-wallet"

	mockVCR.EXPECT().OIDC4VCIEnabled().AnyTimes().Return(true)
	credentialStore := vcrTypes.NewMockWriter(ctrl)
	oidcIssuer := issuer.NewOIDCIssuer(httpServerURL + "/identity")
	mockVCR.EXPECT().GetOIDCIssuer().AnyTimes().Return(oidcIssuer)
	signer := crypto.NewMockJWTSigner(ctrl)
	signer.EXPECT().SignJWT(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("the-signed-jwt", nil)
	resolver := types.NewMockKeyResolver(ctrl)
	resolver.EXPECT().ResolveSigningKeyID(gomock.Any(), nil).Return("key-id", nil)
	mockVCR.EXPECT().GetOIDCWallet(receiverDID).AnyTimes().Return(holder.NewOIDCWallet(receiverDID, receiverIdentifier, credentialStore, signer, resolver))

	vcStored := atomic.Pointer[bool]{}
	credentialStore.EXPECT().StoreCredential(gomock.Any(), nil).DoAndReturn(func(_ vc.VerifiableCredential, _ *time.Time) error {
		vcStored.Store(new(bool))
		return nil
	})

	// Now issue the VC
	err := oidcIssuer.OfferCredential(context.Background(), credential, receiverMetadataURL)
	require.NoError(t, err)

	test.WaitFor(t, func() (bool, error) {
		return vcStored.Load() != nil, nil
	}, 5*time.Second, "time-out waiting for VC to be stored")
}

func TestOIDC4VCIDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockVCR := vcr.NewMockVCR(ctrl)
	api := &oidc4vci_v0.Wrapper{
		VCR: mockVCR,
	}
	mockVCR.EXPECT().OIDC4VCIEnabled().AnyTimes().Return(false)
	httpServerURL := httptest.StartEchoServer(t, api.Routes)

	issuerIdentifier := httpServerURL + "/identity/" + issuerDID.String()
	receiverIdentifier := httpServerURL + "/identity/" + receiverDID.String()
	receiverMetadataURL := receiverIdentifier + "/.well-known/openid-credential-wallet"

	oidcIssuer := issuer.NewOIDCIssuer(issuerIdentifier)
	err := oidcIssuer.OfferCredential(context.Background(), credential, receiverMetadataURL)

	require.ErrorContains(t, err, "unable to load OAuth2 credential client metadata")
	require.ErrorContains(t, err, "404")
}
