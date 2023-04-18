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
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/node"
	"github.com/nuts-foundation/nuts-node/vcr"
	credentialTypes "github.com/nuts-foundation/nuts-node/vcr/credential"
	vdrTypes "github.com/nuts-foundation/nuts-node/vdr/types"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/stretchr/testify/require"
)

var credential = vc.VerifiableCredential{
	Context: []ssi.URI{
		didservice.JWS2020ContextV1URI(),
		credentialTypes.NutsV1ContextURI,
	},
	Type: []ssi.URI{
		ssi.MustParseURI("NutsAuthorizationCredential"),
	},
	IssuanceDate: time.Now().Truncate(time.Second),
}

// TestOIDC4VCIHappyFlow tests issuing a VC using OIDC4VCI.
func TestOIDC4VCIHappyFlow(t *testing.T) {
	auditLogs := audit.CaptureLogs(t)
	ctx := audit.TestContext()
	httpServerURL, system := node.StartServer(t, func(_ string) {
		t.Setenv("NUTS_VCR_OIDC4VCI_ENABLED", "true")
	})
	vcrService := system.FindEngine(new(vcr.VCR)).(vcr.VCR)
	vdrService := system.FindEngine(new(vdrTypes.VDR)).(vdrTypes.VDR)
	didmanService := system.FindEngine(new(didman.Didman)).(didman.Didman)

	// Setup issuer
	var issuerDID did.DID
	{
		issuerDIDDocument, _, err := vdrService.Create(ctx, didservice.DefaultCreationOptions())
		require.NoError(t, err)
		issuerDID = issuerDIDDocument.ID
	}
	// Setup holder
	var holderDID did.DID
	{
		holderDIDDocument, _, err := vdrService.Create(ctx, didservice.DefaultCreationOptions())
		require.NoError(t, err)
		holderDID = holderDIDDocument.ID
		walletMDURL, _ := url.Parse(httpServerURL + "/identity/" + holderDID.String() + "/.well-known/openid-credential-wallet")
		_, err = didmanService.AddEndpoint(ctx, holderDID, "oidc4vci-wallet-metadata", *walletMDURL)
		require.NoError(t, err)
	}

	credential.Issuer = issuerDID.URI()
	credential.ID, _ = ssi.ParseURI(issuerDID.URI().String() + "#1")
	credential.CredentialSubject = append(credential.CredentialSubject, map[string]interface{}{
		"id":           holderDID.URI().String(),
		"purposeOfUse": "test",
	})
	issuedVC, err := vcrService.Issuer().Issue(ctx, credential, true, false)

	require.NoError(t, err)
	require.NotNil(t, issuedVC)

	test.WaitFor(t, func() (bool, error) {
		return auditLogs.Contains(t, audit.VerifiableCredentialRetrievedEvent), nil
	}, 5*time.Second, "credential not retrieved by holder")
}

// TestOIDC4VCIDisabled tests the issuer won't try to issue over OIDC4VCI when it's disabled.
func TestOIDC4VCIDisabled(t *testing.T) {
	ctx := audit.TestContext()
	httpServerURL, system := node.StartServer(t)
	vcrService := system.FindEngine(new(vcr.VCR)).(vcr.VCR)
	vdrService := system.FindEngine(new(vdrTypes.VDR)).(vdrTypes.VDR)
	didmanService := system.FindEngine(new(didman.Didman)).(didman.Didman)

	// Setup issuer/holder
	var issuerAndHolderDID did.DID
	var walletMDURL *url.URL
	{
		didDocument, _, err := vdrService.Create(ctx, didservice.DefaultCreationOptions())
		require.NoError(t, err)
		issuerAndHolderDID = didDocument.ID
		walletMDURL, _ = url.Parse(httpServerURL + "/identity/" + issuerAndHolderDID.String() + "/.well-known/openid-credential-wallet")
		_, err = didmanService.AddEndpoint(ctx, issuerAndHolderDID, "oidc4vci-wallet-metadata", *walletMDURL)
		require.NoError(t, err)
	}

	t.Run("try to issue", func(t *testing.T) {
		credential.Issuer = issuerAndHolderDID.URI()
		credential.ID, _ = ssi.ParseURI(issuerAndHolderDID.URI().String() + "#1")
		credential.CredentialSubject = append(credential.CredentialSubject, map[string]interface{}{
			"id":           issuerAndHolderDID.String(),
			"purposeOfUse": "test",
		})
		issuedVC, err := vcrService.Issuer().Issue(ctx, credential, true, false)

		assert.EqualError(t, err, "")
		assert.Nil(t, issuedVC)
	})
	t.Run("API returns 404", func(t *testing.T) {
		resp, err := http.Get(walletMDURL.String())
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		data, _ := io.ReadAll(resp.Body)
		assert.Equal(t, `{"detail":"openid4vci is disabled","status":404,"title":"Operation failed"}`, string(data))
	})
}
