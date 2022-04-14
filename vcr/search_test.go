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
	"testing"
	"time"

	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/stretchr/testify/assert"
)

func TestVCR_Search(t *testing.T) {
	vc := jsonld.TestVC()
	testInstance := func(t2 *testing.T) (mockContext, []SearchTerm) {
		ctx := newMockContext(t2)

		// add document
		doc := []byte(jsonld.TestCredential)
		err := ctx.vcr.credentialCollection().Add([]leia.Document{doc})
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		// query
		eyeColourPath := []string{"https://www.w3.org/2018/credentials#credentialSubject", "http://example.org/human", "http://example.org/eyeColour"}
		searchTerms := []SearchTerm{
			{
				IRIPath: eyeColourPath,
				Value:   "blue",
				Type:    Prefix,
			},
		}
		return ctx, searchTerms
	}

	reqCtx := context.Background()
	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}
	defer func() {
		timeFunc = time.Now
	}()

	t.Run("ok", func(t *testing.T) {
		ctx, searchTerms := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.vcr.Trust(vc.Type[1], vc.Issuer)

		searchResult, err := ctx.vcr.Search(reqCtx, searchTerms, false, &now)

		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, searchResult, 1) {
			return
		}

		cs := searchResult[0].CredentialSubject[0]
		m := cs.(map[string]interface{})
		c := m["human"].(map[string]interface{})
		assert.Equal(t, "fair", c["hairColour"])
	})

	t.Run("ok - not nil", func(t *testing.T) {
		ctx, _ := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.vcr.Trust(vc.Type[1], vc.Issuer)
		searchTerms := []SearchTerm{
			{
				IRIPath: []string{"https://www.w3.org/2018/credentials#credentialSubject", "http://example.org/human", "http://example.org/eyeColour"},
				Type:    NotNil,
			},
		}

		searchResult, err := ctx.vcr.Search(reqCtx, searchTerms, false, &now)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, searchResult, 1)
	})

	t.Run("ok - untrusted", func(t *testing.T) {
		ctx, searchTerms := testInstance(t)

		searchResult, err := ctx.vcr.Search(reqCtx, searchTerms, false, &now)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, searchResult, 0, "expected no results since the credential is not trusted")
	})

	t.Run("ok - untrusted but allowed", func(t *testing.T) {
		ctx, searchTerms := testInstance(t)

		searchResult, err := ctx.vcr.Search(reqCtx, searchTerms, true, &now)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, searchResult, 1, "expected 1 results since the allowUntrusted flag is set")
	})

	// Todo: use ldproof revocation and issuer store after switch
	t.Run("ok - revoked", func(t *testing.T) {
		ctx, searchTerms := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		rev := []byte(concept.TestRevocation)
		ctx.vcr.store.JSONCollection(revocationCollection).Add([]leia.Document{rev})

		creds, err := ctx.vcr.Search(reqCtx, searchTerms, true, nil)

		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, creds, 0)
	})
}
