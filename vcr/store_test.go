/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"crypto/ecdsa"
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-leia/v2"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"os"
	"path"
	"testing"
	"time"

	did2 "github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

func TestVcr_StoreCredential(t *testing.T) {
	// load VC
	target := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &target)
	did, _ := did2.ParseDIDURL(target.Issuer.String())

	// load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()
		timeFunc = func() time.Time {
			return now
		}
		defer func() {
			timeFunc = time.Now
		}()

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), nil).Return(pk, nil)
		ctx.docResolver.EXPECT().Resolve(*did, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, nil)

		err := ctx.vcr.StoreCredential(target, nil)

		assert.NoError(t, err)
	})

	t.Run("ok - with validAt", func(t *testing.T) {
		ctx := newMockContext(t)
		now := time.Now()

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), &now).Return(pk, nil)
		ctx.docResolver.EXPECT().Resolve(*did, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, nil)

		err := ctx.vcr.StoreCredential(target, &now)

		assert.NoError(t, err)
	})

	t.Run("error - validation", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.vcr.StoreCredential(vc.VerifiableCredential{}, nil)

		assert.Error(t, err)
	})
}

func TestVcr_StoreRevocation(t *testing.T) {
	// load VC
	r := credential.Revocation{}
	rJSON, _ := os.ReadFile("test/revocation.json")
	json.Unmarshal(rJSON, &r)

	// load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.keyResolver.EXPECT().ResolveSigningKey(gomock.Any(), gomock.Any()).Return(pk, nil)

		err := ctx.vcr.StoreRevocation(r)

		assert.NoError(t, err)
	})

	t.Run("error - validation", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.vcr.StoreRevocation(credential.Revocation{})

		assert.Error(t, err)
	})
}
func newTestCredentialStoreInstance(t *testing.T) (CredentialStoreBackend, concept.Registry) {
	t.Helper()
	testDir := io.TestDirectory(t)
	leiaDBPath := path.Join(testDir, "vcr", "credentials.db")
	conceptRegistry := concept.NewRegistry()

	store, err := NewLeiaStore(conceptRegistry.Concepts(), leiaDBPath, false)
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	leiaStore := store.(*leiaCredentialStore)

	// init template
	err = conceptRegistry.Add(concept.ExampleConfig)
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}

	// reindex
	err = leiaStore.initIndices([]concept.Config{concept.ExampleConfig})
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}

	// add document
	doc := leia.DocumentFromString(concept.TestHumanCredential1)
	err = leiaStore.db.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	doc = leia.DocumentFromString(concept.TestHumanCredential2)
	err = leiaStore.db.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}

	return leiaStore, conceptRegistry
}

func TestLeiaCredentialStore_SearchCredential(t *testing.T) {
	reqCtx := context.Background()
	store, conceptRegistry := newTestCredentialStoreInstance(t)

	t.Run("ok - blue eyes", func(t *testing.T) {
		q, err := conceptRegistry.QueryFor(concept.ExampleConcept)
		if !assert.NoError(t, err) {
			t.Fatal(err)
		}
		q.AddClause(concept.Prefix("human.eyeColour", "blue"))

		creds, err := store.SearchCredential(reqCtx, q)

		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, creds, 1) {
			return
		}

		cs := creds[0].CredentialSubject[0]
		m := cs.(map[string]interface{})
		c := m["human"].(map[string]interface{})
		assert.Equal(t, "fair", c["hairColour"])
		assert.Equal(t, "blue/grey", c["eyeColour"])
	})

	t.Run("ok - yellow eyes", func(t *testing.T) {
		q, err := conceptRegistry.QueryFor(concept.ExampleConcept)
		if !assert.NoError(t, err) {
			t.Fatal(err)
		}
		q.AddClause(concept.Prefix("human.eyeColour", "yellow"))

		creds, err := store.SearchCredential(reqCtx, q)

		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, creds, 1) {
			return
		}

		cs := creds[0].CredentialSubject[0]
		m := cs.(map[string]interface{})
		c := m["human"].(map[string]interface{})
		assert.Equal(t, "fair", c["hairColour"])
		assert.Equal(t, "yellow", c["eyeColour"])
	})

	t.Run("ok - wrong eyeColour", func(t *testing.T) {
		q, err := conceptRegistry.QueryFor(concept.ExampleConcept)
		if !assert.NoError(t, err) {
			t.Fatal(err)
		}
		q.AddClause(concept.Prefix("human.eyeColour", "green"))

		creds, err := store.SearchCredential(reqCtx, q)

		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, creds, 0) {
			return
		}
	})

	t.Run("error - context cancelled", func(t *testing.T) {
		q, err := conceptRegistry.QueryFor(concept.ExampleConcept)
		if !assert.NoError(t, err) {
			t.Fatal(err)
		}
		q.AddClause(concept.Prefix("human.eyeColour", "blue"))
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		creds, err := store.SearchCredential(cancelledCtx, q)

		if !assert.EqualError(t, err, "context canceled") {
			return
		}
		if !assert.Len(t, creds, 0) {
			return
		}
	})
}

func TestLeiaCredentialStore_CredentialIssuers(t *testing.T) {
	t.Run("ok - gets a list of issuers", func(t *testing.T) {
		store, _ := newTestCredentialStoreInstance(t)
		cType, _ := ssi.ParseURI(concept.ExampleType)
		res, err := store.CredentialIssuers(*cType)
		assert.NoError(t, err)
		assert.Len(t, res, 2, "expected 2 issuers")
		assert.Equal(t, res[0].String(), "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")
		assert.Equal(t, res[1].String(), "did:nuts:BfQRsmgryywR3goAsECwjGHbCNGGqKdMvmrLHV6UgZsx")
	})

	t.Run("error - unknown credential type", func(t *testing.T) {
		store, _ := newTestCredentialStoreInstance(t)
		cType, err := ssi.ParseURI("unknownType")
		if !assert.NoError(t, err) {
			return
		}
		res, err := store.CredentialIssuers(*cType)
		assert.EqualError(t, err, "invalid credential")
		assert.Len(t, res, 0, "expected 2 issuers")
	})
}
