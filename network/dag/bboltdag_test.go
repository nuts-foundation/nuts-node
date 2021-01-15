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
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"path"
	"sort"
	"strings"
	"testing"
)

var bboltDAGCreator = func(t *testing.T) DAG {
	if dag, _, err := NewBBoltDAG(path.Join(io.TestDirectory(t), "dag.db")); err != nil {
		t.Fatal(err)
		return nil
	} else {
		return dag
	}
}

func TestBBoltDAG_Add(t *testing.T) {
	DAGTest_Add(bboltDAGCreator, t)
}

func TestBBoltDAG_All(t *testing.T) {
	DAGTest_All(bboltDAGCreator, t)
}

func TestBBoltDAG_MissingDocuments(t *testing.T) {
	DAGTest_MissingDocuments(bboltDAGCreator, t)
}

func TestBBoltDAG_Walk(t *testing.T) {
	DAGTest_Walk(bboltDAGCreator, t)
}

func TestBBoltDAG_Get(t *testing.T) {
	DAGTest_Get(bboltDAGCreator, t)
}

func TestBBoltDAG_GetByPayloadHash(t *testing.T) {
	DAGTest_GetByPayloadHash(bboltDAGCreator, t)
}

func TestBBoltDAG_PayloadStore(t *testing.T) {
	PayloadStoreTest(func(t *testing.T) PayloadStore {
		return bboltDAGCreator(t).(PayloadStore)
	}, t)
}

func TestBBoltDAG_Subscribe(t *testing.T) {
	DAGTest_Subscribe(bboltDAGCreator, t)
}

func TestBBoltDAG_Diagnostics(t *testing.T) {
	dag := bboltDAGCreator(t).(*bboltDAG)
	doc1 := CreateTestDocument(2)
	dag.Add(doc1)
	diagnostics := dag.Diagnostics()
	assert.Len(t, diagnostics, 3)
	// Assert actual diagnostics
	lines := make([]string, 0)
	for _, diagnostic := range diagnostics {
		lines = append(lines, diagnostic.Name()+": "+diagnostic.String())
	}
	sort.Strings(lines)
	actual := strings.Join(lines, "\n")
	assert.Equal(t, `[DAG] Heads: [`+doc1.Ref().String()+`]
[DAG] Number of documents: 2
[DAG] Stored document size (bytes): 0`, actual)
}

func Test_parseHashList(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Empty(t, parseHashList([]byte{}))
	})
	t.Run("1 entry", func(t *testing.T) {
		h1 := hash.SHA256Sum([]byte("Hello, World!"))
		actual := parseHashList(h1[:])
		assert.Len(t, actual, 1)
		assert.Equal(t, hash.FromSlice(h1[:]), actual[0])
	})
	t.Run("2 entries", func(t *testing.T) {
		h1 := hash.SHA256Sum([]byte("Hello, World!"))
		h2 := hash.SHA256Sum([]byte("Hello, All!"))
		actual := parseHashList(append(h1[:], h2[:]...))
		assert.Len(t, actual, 2)
		assert.Equal(t, hash.FromSlice(h1[:]), actual[0])
		assert.Equal(t, hash.FromSlice(h2[:]), actual[1])
	})
	t.Run("2 entries, dangling bytes", func(t *testing.T) {
		h1 := hash.SHA256Sum([]byte("Hello, World!"))
		h2 := hash.SHA256Sum([]byte("Hello, All!"))
		input := append(h1[:], h2[:]...)
		input = append(input, 1, 2, 3) // Add some dangling bytes
		actual := parseHashList(input)
		assert.Len(t, actual, 2)
		assert.Equal(t, hash.FromSlice(h1[:]), actual[0])
		assert.Equal(t, hash.FromSlice(h2[:]), actual[1])
	})
}
