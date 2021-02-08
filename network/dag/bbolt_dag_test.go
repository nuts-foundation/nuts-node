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
	"go.etcd.io/bbolt"
	"path"
	"sort"
	"strings"
	"testing"
)

func createBBoltDB(testDirectory string) *bbolt.DB {
	db, err := bbolt.Open(path.Join(testDirectory, "dag.db"), 0600, bbolt.DefaultOptions)
	if err != nil {
		panic(err)
	}
	return db
}

func createDAG(t *testing.T) DAG {
	testDirectory := io.TestDirectory(t)
	return NewBBoltDAG(createBBoltDB(testDirectory))
}

// trackingVisitor just keeps track of which nodes were visited in what order.
type trackingVisitor struct {
	documents []Document
}

func (n *trackingVisitor) Accept(document Document) bool {
	n.documents = append(n.documents, document)
	return true
}

func (n trackingVisitor) JoinRefsAsString() string {
	var contents []string
	for _, document := range n.documents {
		val := strings.TrimLeft(document.PayloadHash().String(), "0")
		if val == "" {
			val = "0"
		}
		contents = append(contents, val)
	}
	return strings.Join(contents, ", ")
}

func TestBBoltDAG_All(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := createDAG(t)
		doc := CreateTestDocumentWithJWK(1)

		err := graph.Add(doc)

		if !assert.NoError(t, err) {
			return
		}

		actual, err := graph.All()
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, actual, 1)
		assert.Equal(t, doc, actual[0])
	})
}

func TestBBoltDAG_Get(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := createDAG(t)
		document := CreateTestDocumentWithJWK(1)
		_ = graph.Add(document)
		actual, err := graph.Get(document.Ref())
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, document, actual)
	})
	t.Run("not found", func(t *testing.T) {
		graph := createDAG(t)
		actual, err := graph.Get(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
}

func TestBBoltDAG_Add(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := createDAG(t)
		doc := CreateTestDocumentWithJWK(0)

		err := graph.Add(doc)

		assert.NoError(t, err)
		visitor := trackingVisitor{}
		root, _ := graph.Root()
		err = graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, visitor.documents, 1)
		assert.Equal(t, doc.Ref(), visitor.documents[0].Ref())
		present, _ := graph.IsPresent(doc.Ref())
		assert.True(t, present)
	})
	t.Run("duplicate", func(t *testing.T) {
		graph := createDAG(t)
		doc := CreateTestDocumentWithJWK(0)

		_ = graph.Add(doc)
		err := graph.Add(doc)
		assert.NoError(t, err)
		actual, _ := graph.All()
		assert.Len(t, actual, 1)
	})
	t.Run("second root", func(t *testing.T) {
		graph := createDAG(t)
		root1 := CreateTestDocumentWithJWK(1)
		root2 := CreateTestDocumentWithJWK(2)

		_ = graph.Add(root1)
		err := graph.Add(root2)
		assert.EqualError(t, err, "root document already exists")
		actual, _ := graph.All()
		assert.Len(t, actual, 1)
	})
	t.Run("ok - out of order", func(t *testing.T) {
		graph := createDAG(t)
		documents := graphF()

		for i := len(documents) - 1; i >= 0; i-- {
			err := graph.Add(documents[i])
			if !assert.NoError(t, err) {
				return
			}
		}

		visitor := trackingVisitor{}
		root, _ := graph.Root()
		err := graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}
		assert.Regexp(t, "0, (1, 2|2, 1), (3, 4|4, 3), 5", visitor.JoinRefsAsString())
	})
	t.Run("error - cyclic graph", func(t *testing.T) {
		t.Skip("Algorithm for detecting cycles is not yet decided on")
		// A -> B -> C -> B
		A := CreateTestDocumentWithJWK(0)
		B := CreateTestDocumentWithJWK(1, A.Ref()).(*document)
		C := CreateTestDocumentWithJWK(2, B.Ref())
		B.prevs = append(B.prevs, C.Ref())

		graph := createDAG(t)
		err := graph.Add(A, B, C)
		assert.EqualError(t, err, "")
	})
}

func TestBBoltDAG_Walk(t *testing.T) {
	t.Run("ok - empty graph", func(t *testing.T) {
		graph := createDAG(t)
		visitor := trackingVisitor{}

		root, _ := graph.Root()
		err := graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.documents)
	})
}

func TestBBoltDAG_MissingDocuments(t *testing.T) {
	A := CreateTestDocumentWithJWK(0)
	B := CreateTestDocumentWithJWK(1, A.Ref())
	C := CreateTestDocumentWithJWK(2, B.Ref())
	t.Run("no missing documents (empty graph)", func(t *testing.T) {
		graph := createDAG(t)
		assert.Empty(t, graph.MissingDocuments())
	})
	t.Run("no missing documents (non-empty graph)", func(t *testing.T) {
		graph := createDAG(t)
		graph.Add(A, B, C)
		assert.Empty(t, graph.MissingDocuments())
	})
	t.Run("missing documents (non-empty graph)", func(t *testing.T) {
		graph := createDAG(t)
		graph.Add(A, C)
		assert.Len(t, graph.MissingDocuments(), 1)
		// Now add missing document B and assert there are no more missing documents
		graph.Add(B)
		assert.Empty(t, graph.MissingDocuments())
	})
}
func TestBBoltDAG_Observe(t *testing.T) {
	graph := createDAG(t)
	var actual interface{}
	graph.RegisterObserver(func(subject interface{}) {
		actual = subject
	})
	expected := CreateTestDocumentWithJWK(1)
	err := graph.Add(expected)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestBBoltDAG_GetByPayloadHash(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := createDAG(t)
		document := CreateTestDocumentWithJWK(1)
		_ = graph.Add(document)
		actual, err := graph.GetByPayloadHash(document.PayloadHash())
		assert.Len(t, actual, 1)
		assert.NoError(t, err)
		assert.Equal(t, document, actual[0])
	})
	t.Run("not found", func(t *testing.T) {
		graph := createDAG(t)
		actual, err := graph.GetByPayloadHash(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
}

func TestBBoltDAG_Diagnostics(t *testing.T) {
	dag := createDAG(t).(*bboltDAG)
	doc1 := CreateTestDocumentWithJWK(2)
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
