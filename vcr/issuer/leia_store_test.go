/*
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

package issuer

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

func TestNewLeiaStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
		sut, err := NewLeiaStore(issuerStorePath)

		assert.NoError(t, err)
		assert.IsType(t, &leiaStore{}, sut)
	})

	t.Run("error", func(t *testing.T) {
		// use the filename of this test, which should fail
		sut, err := NewLeiaStore("leia_store_test.go")

		assert.Contains(t, err.Error(), "failed to create leiaStore: invalid database")
		assert.Nil(t, sut)
	})
}

func TestLeiaStore_Close(t *testing.T) {
	testDir := io.TestDirectory(t)
	issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
	sut, _ := NewLeiaStore(issuerStorePath)
	err := sut.Close()
	assert.NoError(t, err)
}

func Test_leiaStore_StoreAndSearchCredential(t *testing.T) {
	vcToStore := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(concept.TestCredential), &vcToStore)

	t.Run("store", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
		sut, err := NewLeiaStore(issuerStorePath)
		if !assert.NoError(t, err) {
			return
		}

		err = sut.StoreCredential(vcToStore)
		assert.NoError(t, err)

		t.Run("and search", func(t *testing.T) {
			issuerDID, _ := did.ParseDID(vcToStore.Issuer.String())
			subjectID, _ := ssi.ParseURI("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

			t.Run("for all issued credentials for a issuer", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Context[1], vcToStore.Type[0], *issuerDID, nil)
				assert.NoError(t, err)
				if !assert.Len(t, res, 1) {
					return
				}

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("for all issued credentials for a issuer and subject", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, subjectID)
				assert.NoError(t, err)
				if !assert.Len(t, res, 1) {
					return
				}

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("no results", func(t *testing.T) {

				t.Run("unknown issuer", func(t *testing.T) {
					unknownIssuerDID, _ := did.ParseDID("did:nuts:123")
					res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *unknownIssuerDID, nil)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}
				})

				t.Run("unknown credentialType", func(t *testing.T) {
					unknownType, _ := ssi.ParseURI("unknownType")
					res, err := sut.SearchCredential(vcToStore.Context[0], *unknownType, *issuerDID, nil)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}
				})

				t.Run("unknown subject", func(t *testing.T) {
					unknownSubject, _ := ssi.ParseURI("did:nuts:unknown")
					res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, unknownSubject)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}

				})
			})

		})
	})

}
