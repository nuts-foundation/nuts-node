/*
 * Copyright (C) 2021. Nuts community
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

package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewDocument(t *testing.T) {
	payloadHash, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	t.Run("ok", func(t *testing.T) {
		hash, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")

		document, err := NewDocument(payloadHash, "some/type", []hash2.SHA256Hash{hash})

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "some/type", document.PayloadType())
		assert.Equal(t, document.PayloadHash(), payloadHash)
		assert.Equal(t, []hash2.SHA256Hash{hash}, document.Previous())
		assert.Equal(t, Version(1), document.Version())
	})
	t.Run("error - type empty", func(t *testing.T) {
		document, err := NewDocument(payloadHash, "", nil)
		assert.EqualError(t, err, errInvalidPayloadType.Error())
		assert.Nil(t, document)
	})
	t.Run("error - type not a MIME type", func(t *testing.T) {
		document, err := NewDocument(payloadHash, "foo", nil)
		assert.EqualError(t, err, errInvalidPayloadType.Error())
		assert.Nil(t, document)
	})
	t.Run("error - invalid prev", func(t *testing.T) {
		document, err := NewDocument(payloadHash, "foo/bar", []hash2.SHA256Hash{hash2.EmptyHash()})
		assert.EqualError(t, err, errInvalidPrevs.Error())
		assert.Nil(t, document)
	})
}

func Test_document_Getters(t *testing.T) {
	payload, _ := hash2.ParseHex("452d9e89d5bd5d9225fb6daecd579e7388a166c7661ca04e47fd3cd8446e4620")
	timelineID, _ := hash2.ParseHex("f33b5cae968cb88f157999b3551ab0863d2a8f0b")
	prev1, _ := hash2.ParseHex("3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986")
	prev2, _ := hash2.ParseHex("b3f2c3c396da1a949d214e4c2fe0fc9fb5f2a68ff1860df4ef10c9835e62e7c1")
	doc := document{
		prevs:           []hash2.SHA256Hash{prev1, prev2},
		payload:         payload,
		payloadType:     "foo/bar",
		signingTime:     time.Unix(1023323333, 0),
		version:         10,
		timelineID:      timelineID,
		timelineVersion: 10,
	}
	doc.setData([]byte{1, 2, 3})

	assert.Equal(t, doc.prevs, doc.Previous())
	assert.Equal(t, doc.payload, doc.PayloadHash())
	assert.Equal(t, doc.payloadType, doc.PayloadType())
	assert.Equal(t, doc.signingTime, doc.SigningTime())
	assert.Equal(t, doc.version, doc.Version())
	assert.Equal(t, doc.timelineID, doc.TimelineID())
	assert.Equal(t, doc.timelineVersion, doc.TimelineVersion())
	assert.Equal(t, doc.data, doc.Data())
	assert.False(t, doc.Ref().Empty())
}

func Test_document_MarshalJSON(t *testing.T) {
	expected, _, _ := CreateTestDocument(1)
	data, err := json.Marshal(expected)
	assert.NoError(t, err)
	assert.Equal(t, `"`+string(expected.Data())+`"`, string(data))
}

func generateKey() *ecdsa.PrivateKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func generateRSAKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	return key
}
