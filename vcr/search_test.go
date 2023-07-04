/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package vcr

import (
	"context"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
	"time"

	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestVCR_Search(t *testing.T) {
	vc := jsonld.TestVC()

	// Create query
	eyeColourPath := []string{"https://www.w3.org/2018/credentials#credentialSubject", "http://example.org/human", "http://example.org/eyeColour"}
	prefixSearchTerms := []SearchTerm{
		{
			IRIPath: eyeColourPath,
			Value:   "blue",
			Type:    Prefix,
		},
	}

	testInstance := func(t2 *testing.T) mockContext {
		ctx := newMockContext(t2)

		// add document
		doc := []byte(jsonld.TestCredential)
		err := ctx.vcr.credentialCollection().Add([]leia.Document{doc})
		require.NoError(t, err)
		return ctx
	}

	reqCtx := context.Background()
	now := time.Now()

	t.Run("ok - exact match", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.vcr.Trust(vc.Type[1], vc.Issuer)

		exactSearchTerms := []SearchTerm{
			{
				IRIPath: eyeColourPath,
				Value:   "blue/grey",
				Type:    Exact,
			},
		}

		searchResult, err := ctx.vcr.Search(reqCtx, exactSearchTerms, false, &now)

		require.NoError(t, err)
		require.Len(t, searchResult, 1)

		cs := searchResult[0].CredentialSubject[0]
		m := cs.(map[string]interface{})
		c := m["human"].(map[string]interface{})
		assert.Equal(t, "fair", c["hairColour"])
	})
	t.Run("ok - default (exact match)", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.vcr.Trust(vc.Type[1], vc.Issuer)

		exactSearchTerms := []SearchTerm{
			{
				IRIPath: eyeColourPath,
				Value:   "blue/grey",
			},
		}

		searchResult, err := ctx.vcr.Search(reqCtx, exactSearchTerms, false, &now)

		assert.NoError(t, err)
		assert.Len(t, searchResult, 1)
	})

	t.Run("ok - prefix", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.vcr.Trust(vc.Type[1], vc.Issuer)

		searchResult, err := ctx.vcr.Search(reqCtx, prefixSearchTerms, false, &now)

		assert.NoError(t, err)
		assert.Len(t, searchResult, 1)
	})

	t.Run("ok - not nil", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.vcr.Trust(vc.Type[1], vc.Issuer)
		searchTerms := []SearchTerm{
			{
				IRIPath: []string{"https://www.w3.org/2018/credentials#credentialSubject", "http://example.org/human", "http://example.org/eyeColour"},
				Type:    NotNil,
			},
		}

		searchResult, err := ctx.vcr.Search(reqCtx, searchTerms, false, &now)

		assert.NoError(t, err)
		assert.Len(t, searchResult, 1)
	})

	t.Run("ok - untrusted", func(t *testing.T) {
		ctx := testInstance(t)

		searchResult, err := ctx.vcr.Search(reqCtx, prefixSearchTerms, false, &now)
		require.NoError(t, err)

		assert.Len(t, searchResult, 0, "expected no results since the credential is not trusted")
	})

	t.Run("ok - untrusted but allowed", func(t *testing.T) {
		ctx := testInstance(t)

		searchResult, err := ctx.vcr.Search(reqCtx, prefixSearchTerms, true, &now)
		require.NoError(t, err)

		assert.Len(t, searchResult, 1, "expected 1 results since the allowUntrusted flag is set")
	})

	// Todo: use ldproof revocation and issuer store after switch
	t.Run("ok - revoked", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		mockVerifier := verifier.NewMockVerifier(ctx.ctrl)
		ctx.vcr.verifier = mockVerifier
		mockVerifier.EXPECT().Verify(vc, true, false, gomock.Any()).Return(types.ErrRevoked)

		creds, err := ctx.vcr.Search(reqCtx, prefixSearchTerms, true, nil)

		require.NoError(t, err)

		assert.Len(t, creds, 0)
	})
}

func Test_formatFilteredVCsLogMessage(t *testing.T) {
	input := map[string]int{
		types.ErrRevoked.Error():   2,
		types.ErrUntrusted.Error(): 10,
		io.EOF.Error():             1,
	}
	msg := formatFilteredVCsLogMessage(input)
	assert.Equal(t, "Filtered 13 invalid VCs from search results (more info on TRACE): 'EOF' (1 times), 'credential is revoked' (2 times), 'credential issuer is untrusted' (10 times)", msg)
}
