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
	"path"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestNewLeiaStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
		sut, err := NewLeiaIssuerStore(issuerStorePath)

		assert.NoError(t, err)
		assert.IsType(t, &leiaIssuerStore{}, sut)
	})

	t.Run("error", func(t *testing.T) {
		sut, err := NewLeiaIssuerStore("/")

		assert.Contains(t, err.Error(), "failed to create leiaIssuerStore:")
		assert.Nil(t, sut)
	})
}

func TestLeiaStore_Close(t *testing.T) {
	testDir := io.TestDirectory(t)
	issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
	sut, _ := NewLeiaIssuerStore(issuerStorePath)
	err := sut.Close()
	assert.NoError(t, err)
}

func Test_leiaStore_StoreAndSearchCredential(t *testing.T) {
	vcToStore := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestCredential), &vcToStore)

	t.Run("store", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
		sut, err := NewLeiaIssuerStore(issuerStorePath)
		if !assert.NoError(t, err) {
			return
		}

		err = sut.StoreCredential(vcToStore)
		assert.NoError(t, err)

		t.Run("and search", func(t *testing.T) {
			issuerDID, _ := did.ParseDID(vcToStore.Issuer.String())
			subjectID := ssi.MustParseURI("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

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
				res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, &subjectID)
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
					unknownType := ssi.MustParseURI("unknownType")
					res, err := sut.SearchCredential(vcToStore.Context[0], unknownType, *issuerDID, nil)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}
				})

				t.Run("unknown subject", func(t *testing.T) {
					unknownSubject := ssi.MustParseURI("did:nuts:unknown")
					res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, &unknownSubject)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}

				})
			})

		})
	})

}

func Test_leiaStore_GetCredential(t *testing.T) {
	vcToGet := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestCredential), &vcToGet)

	newStore := func(t2 *testing.T) Store {
		t2.Helper()
		testDir := io.TestDirectory(t)
		issuerStorePath := path.Join(testDir, "vcr", "issued-credentials.db")
		store, err := NewLeiaIssuerStore(issuerStorePath)
		if !assert.NoError(t, err) {
			t.Fatal()
		}
		return store
	}

	t.Run("with a known credential", func(t *testing.T) {
		store := newStore(t)
		assert.NoError(t, store.StoreCredential(vcToGet))
		t.Run("it finds the credential by id", func(t *testing.T) {
			foundCredential, err := store.GetCredential(*vcToGet.ID)
			assert.NoError(t, err)
			assert.Equal(t, *foundCredential, vcToGet)
		})
	})

	t.Run("no results", func(t *testing.T) {
		store := newStore(t)
		foundCredential, err := store.GetCredential(*vcToGet.ID)
		assert.EqualError(t, err, ErrNotFound.Error())
		assert.Nil(t, foundCredential)
	})

	t.Run("multiple results", func(t *testing.T) {
		store := newStore(t)
		// store once
		assert.NoError(t, store.StoreCredential(vcToGet))
		// store twice
		lstore := store.(*leiaIssuerStore)
		rawStructWithSameID := struct {
			ID *ssi.URI `json:"id,omitempty"`
		}{ID: vcToGet.ID}
		asBytes, _ := json.Marshal(rawStructWithSameID)
		lstore.issuedCredentials.Add([]leia.Document{asBytes})

		t.Run("it fails", func(t *testing.T) {
			foundCredential, err := store.GetCredential(*vcToGet.ID)
			assert.EqualError(t, err, "found more than one credential by id")
			assert.Nil(t, foundCredential)
		})
	})
}
