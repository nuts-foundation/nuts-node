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

package didstore

import (
	"encoding/json"
	"path"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/require"

	"github.com/nuts-foundation/nuts-node/crypto/hash"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
)

const moduleName = "VDR"

var testDID = did.MustParseDID("did:nuts:test")

// marshal/unmarshal safe notation
var testServiceA = did.Service{ID: ssi.MustParseURI("did:nuts:service:a"), ServiceEndpoint: []interface{}{"http://a"}}
var testServiceB = did.Service{ID: ssi.MustParseURI("did:nuts:service:b"), ServiceEndpoint: []interface{}{"http://b"}}

func NewTestStore(t *testing.T) *store {
	s := New(storage.NewTestStorageEngine(path.Join(io.TestDirectory(t))).GetProvider(moduleName)).(*store)
	err := s.Configure(core.ServerConfig{})
	require.NoError(t, err)
	return s
}

func add(t *testing.T, tl *store, doc did.Document, tx Transaction) {
	err := tl.Add(doc, tx)
	require.NoError(t, err)
}

func newTestTransaction(document did.Document, prevs ...hash.SHA256Hash) Transaction {
	documentBytes, _ := json.Marshal(document)
	return Transaction{
		Ref:         hash.RandomHash(),
		PayloadHash: hash.SHA256Sum(documentBytes),
		SigningTime: time.Now(),
		Previous:    prevs,
	}
}

func TestTransaction(document did.Document) Transaction {
	return newTestTransaction(document)
}
