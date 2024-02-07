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

package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"io"
	"reflect"
	"testing"
	"time"
)

func TestCopy(t *testing.T) {
	timeBefore := time.Now().Add(time.Hour * -24)
	timeNow := time.Now()
	timeLater := time.Now().Add(time.Hour * +24)
	h, _ := hash.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")

	meta := DocumentMetadata{
		Created:            timeBefore,
		Updated:            &timeNow,
		Hash:               h,
		PreviousHash:       &h,
		Deactivated:        false,
		SourceTransactions: []hash.SHA256Hash{h},
	}
	numFields := 6

	t.Run("returns error if metadata can be manipulated", func(t *testing.T) {
		var metaCopy DocumentMetadata

		// Copy
		metaCopy = meta.Copy()
		assert.True(t, reflect.DeepEqual(meta, metaCopy))

		// Updated
		metaCopy = meta.Copy()
		*metaCopy.Updated = timeLater
		assert.False(t, reflect.DeepEqual(meta, metaCopy))

		// Hash
		metaCopy.Hash[0] = 0
		assert.NotEqual(t, metaCopy.Hash, meta.Hash, "Hash is not deep-copied")

		// PreviousHash
		metaCopy.PreviousHash[0] = 0
		assert.NotEqual(t, metaCopy.PreviousHash, meta.PreviousHash, "PreviousHash is not deep-copied")

		// SourceTransactions
		metaCopy.SourceTransactions[0] = hash.SHA256Hash{20}
		assert.NotEqual(t, metaCopy.SourceTransactions, meta.SourceTransactions, "SourceTransactions is not deep-copied")

		// if this test fails, please make sure the Copy() method is updated as well!
		assert.Equal(t, numFields, reflect.TypeOf(DocumentMetadata{}).NumField())
	})
}

func TestDocumentMetadata_IsConflicted(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		assert.True(t, DocumentMetadata{SourceTransactions: []hash.SHA256Hash{hash.EmptyHash(), hash.EmptyHash()}}.IsConflicted())
	})

	t.Run("false", func(t *testing.T) {
		assert.False(t, DocumentMetadata{}.IsConflicted())
	})
}
func Test_deactivatedError_Is(t *testing.T) {
	assert.ErrorIs(t, ErrDeactivated, ErrDeactivated)
	assert.ErrorIs(t, ErrNoActiveController, ErrDeactivated)
	assert.NotErrorIs(t, io.EOF, ErrDeactivated)
}

func newDidDoc() did.Document {
	return newDidDocWithDID(did.MustParseDID("did:example:sakjsakldjsakld"))
}

func newDidDocWithDID(id did.DID) did.Document {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyID := did.DIDURL{DID: id}
	keyID.Fragment = "key-1"
	vm, _ := did.NewVerificationMethod(keyID, ssi.JsonWebKey2020, id, privateKey.Public())
	doc := did.Document{
		ID: id,
	}
	doc.AddAssertionMethod(vm)
	return doc
}

func TestDIDResolverRouter_Resolve(t *testing.T) {
	doc := newDidDoc()
	t.Run("ok, 1 resolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		resolver := NewMockDIDResolver(ctrl)
		resolver.EXPECT().Resolve(doc.ID, gomock.Any()).Return(&doc, nil, nil)
		router := &DIDResolverRouter{}
		router.Register(doc.ID.Method, resolver)

		actual, _, err := router.Resolve(doc.ID, nil)
		assert.NoError(t, err)
		assert.Equal(t, &doc, actual)
	})
	t.Run("ok, 2 resolvers", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		otherResolver := NewMockDIDResolver(ctrl)
		resolver := NewMockDIDResolver(ctrl)
		resolver.EXPECT().Resolve(doc.ID, gomock.Any()).Return(&doc, nil, nil)
		router := &DIDResolverRouter{}
		router.Register(doc.ID.Method, resolver)
		router.Register("test2", otherResolver)

		actual, _, err := router.Resolve(doc.ID, nil)
		assert.NoError(t, err)
		assert.Equal(t, &doc, actual)
	})
	t.Run("error - resolver not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		otherResolver := NewMockDIDResolver(ctrl)
		router := &DIDResolverRouter{}
		router.Register("other", otherResolver)

		actual, _, err := router.Resolve(doc.ID, nil)
		assert.EqualError(t, err, "DID method not supported")
		assert.Nil(t, actual)
	})
}

func TestIsFunctionalResolveError(t *testing.T) {
	assert.True(t, IsFunctionalResolveError(ErrNotFound))
	assert.True(t, IsFunctionalResolveError(ErrDeactivated))
	assert.True(t, IsFunctionalResolveError(ErrServiceNotFound))
	assert.True(t, IsFunctionalResolveError(ErrServiceReferenceToDeep))
	assert.True(t, IsFunctionalResolveError(ErrNoActiveController))
	assert.True(t, IsFunctionalResolveError(did.InvalidDIDErr))
	assert.True(t, IsFunctionalResolveError(ServiceQueryError{Err: errors.New("oops")}))

	assert.False(t, IsFunctionalResolveError(errors.New("some error")))
	assert.False(t, IsFunctionalResolveError(ErrDuplicateService))
}

func TestGetDIDFromURL(t *testing.T) {
	t.Run("just it", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("with path", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc/serviceEndpoint")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("with fragment", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc#key-1")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("with params", func(t *testing.T) {
		actual, err := GetDIDFromURL("did:nuts:abc?foo=bar")
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", actual.String())
	})
	t.Run("invalid DID", func(t *testing.T) {
		_, err := GetDIDFromURL("https://example.com")
		assert.Error(t, err)
	})
}
