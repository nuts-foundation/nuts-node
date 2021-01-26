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
	"errors"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

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
		val := strings.TrimLeft(document.Payload().String(), "0")
		if val == "" {
			val = "0"
		}
		contents = append(contents, val)
	}
	return strings.Join(contents, ", ")
}

func DAGTest_All(creator func(t *testing.T) DAG, t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := creator(t)
		doc := CreateTestDocument(1)

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

func DAGTest_Get(creator func(t *testing.T) DAG, t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := creator(t)
		document := CreateTestDocument(1)
		_ = graph.Add(document)
		actual, err := graph.Get(document.Ref())
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, document, actual)
	})
	t.Run("not found", func(t *testing.T) {
		graph := creator(t)
		actual, err := graph.Get(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
}

func DAGTest_Add(creator func(t *testing.T) DAG, t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := creator(t)
		doc := CreateTestDocument(0)

		err := graph.Add(doc)

		assert.NoError(t, err)
		visitor := trackingVisitor{}
		root, _ := graph.Root()
		err = graph.Walk(&BFSWalker{}, visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, visitor.documents, 1)
		assert.Equal(t, doc.Ref(), visitor.documents[0].Ref())
		present, _ := graph.IsPresent(doc.Ref())
		assert.True(t, present)
	})
	t.Run("duplicate", func(t *testing.T) {
		graph := creator(t)
		doc := CreateTestDocument(0)

		_ = graph.Add(doc)
		err := graph.Add(doc)
		assert.NoError(t, err)
		actual, _ := graph.All()
		assert.Len(t, actual, 1)
	})
	t.Run("second root", func(t *testing.T) {
		graph := creator(t)
		root1 := CreateTestDocument(1)
		root2 := CreateTestDocument(2)

		_ = graph.Add(root1)
		err := graph.Add(root2)
		assert.EqualError(t, err, "root document already exists")
		actual, _ := graph.All()
		assert.Len(t, actual, 1)
	})
	t.Run("ok - out of order", func(t *testing.T) {
		_, documents := graphF(creator, t)
		graph := creator(t)

		for i := len(documents) - 1; i >= 0; i-- {
			err := graph.Add(documents[i])
			if !assert.NoError(t, err) {
				return
			}
		}

		visitor := trackingVisitor{}
		root, _ := graph.Root()
		err := graph.Walk(&BFSWalker{}, visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}
		assert.Regexp(t, "0, (1, 2|2, 1), (3, 4|4, 3), 5", visitor.JoinRefsAsString())
	})
	t.Run("error - cyclic graph", func(t *testing.T) {
		t.Skip("Algorithm for detecting cycles is not yet decided on")
		// A -> B -> C -> B
		A := CreateTestDocument(0)
		B := CreateTestDocument(1, A.Ref()).(*document)
		C := CreateTestDocument(2, B.Ref())
		B.prevs = append(B.prevs, C.Ref())

		graph := creator(t)
		err := graph.Add(A, B, C)
		assert.EqualError(t, err, "")
	})
}

func DAGTest_Walk(creator func(t *testing.T) DAG, t *testing.T) {
	t.Run("ok - empty graph", func(t *testing.T) {
		graph := creator(t)
		visitor := trackingVisitor{}

		root, _ := graph.Root()
		err := graph.Walk(&BFSWalker{}, visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.documents)
	})
}

func DAGTest_MissingDocuments(creator func(t *testing.T) DAG, t *testing.T) {
	A := CreateTestDocument(0)
	B := CreateTestDocument(1, A.Ref())
	C := CreateTestDocument(2, B.Ref())
	t.Run("no missing documents (empty graph)", func(t *testing.T) {
		graph := creator(t)
		assert.Empty(t, graph.MissingDocuments())
	})
	t.Run("no missing documents (non-empty graph)", func(t *testing.T) {
		graph := creator(t)
		graph.Add(A, B, C)
		assert.Empty(t, graph.MissingDocuments())
	})
	t.Run("missing documents (non-empty graph)", func(t *testing.T) {
		graph := creator(t)
		graph.Add(A, C)
		assert.Len(t, graph.MissingDocuments(), 1)
		// Now add missing document B and assert there are no more missing documents
		graph.Add(B)
		assert.Empty(t, graph.MissingDocuments())
	})
}

func DAGTest_Subscribe(creator func(t *testing.T) DAG, t *testing.T) {
	t.Run("no subscribers", func(t *testing.T) {
		graph := creator(t)
		document := CreateTestDocument(1)
		_ = graph.Add(document)
		err := graph.(PayloadStore).WritePayload(document.Payload(), []byte("foobar"))
		assert.NoError(t, err)
	})
	t.Run("single subscriber", func(t *testing.T) {
		graph := creator(t)
		document := CreateTestDocument(1)
		received := false
		graph.Subscribe(document.PayloadType(), func(actualDocument Document, actualPayload []byte) error {
			assert.Equal(t, document, actualDocument)
			assert.Equal(t, []byte("foobar"), actualPayload)
			received = true
			return nil
		})
		_ = graph.Add(document)
		err := graph.(PayloadStore).WritePayload(document.Payload(), []byte("foobar"))
		assert.NoError(t, err)
		assert.True(t, received)
	})
	t.Run("multiple subscribers", func(t *testing.T) {
		graph := creator(t)
		document := CreateTestDocument(1)
		calls := 0
		receiver := func(actualDocument Document, actualPayload []byte) error {
			calls++
			return nil
		}
		graph.Subscribe(document.PayloadType(), receiver)
		graph.Subscribe(document.PayloadType(), receiver)
		_ = graph.Add(document)
		err := graph.(PayloadStore).WritePayload(document.Payload(), []byte("foobar"))
		assert.NoError(t, err)
		assert.Equal(t, 2, calls)
	})
	t.Run("multiple subscribers, first fails", func(t *testing.T) {
		graph := creator(t)
		document := CreateTestDocument(1)
		calls := 0
		receiver := func(actualDocument Document, actualPayload []byte) error {
			calls++
			return errors.New("failed")
		}
		graph.Subscribe(document.PayloadType(), receiver)
		graph.Subscribe(document.PayloadType(), receiver)
		_ = graph.Add(document)
		err := graph.(PayloadStore).WritePayload(document.Payload(), []byte("foobar"))
		assert.NoError(t, err)
		assert.Equal(t, 1, calls)
	})
	t.Run("subscriber error", func(t *testing.T) {
		graph := creator(t)
		document := CreateTestDocument(1)
		graph.Subscribe(document.PayloadType(), func(actualDocument Document, actualPayload []byte) error {
			return errors.New("failed")
		})
		_ = graph.Add(document)
		err := graph.(PayloadStore).WritePayload(document.Payload(), []byte("foobar"))
		assert.NoError(t, err)
	})
}

func DAGTest_GetByPayloadHash(creator func(t *testing.T) DAG, t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := creator(t)
		document := CreateTestDocument(1)
		_ = graph.Add(document)
		actual, err := graph.GetByPayloadHash(document.Payload())
		assert.Len(t, actual, 1)
		assert.NoError(t, err)
		assert.Equal(t, document, actual[0])
	})
	t.Run("not found", func(t *testing.T) {
		graph := creator(t)
		actual, err := graph.GetByPayloadHash(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
}

func PayloadStoreTest(creator func(t *testing.T) PayloadStore, t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		payload := []byte("Hello, World!")
		hash := hash.SHA256Sum(payload)
		payloadStore := creator(t)
		// Before, payload should not be present
		present, err := payloadStore.IsPayloadPresent(hash)
		if !assert.NoError(t, err) || !assert.False(t, present) {
			return
		}
		// Add payload
		err = payloadStore.WritePayload(hash, payload)
		if !assert.NoError(t, err) {
			return
		}
		// Now it should be present
		present, err = payloadStore.IsPayloadPresent(hash)
		if !assert.NoError(t, err) || !assert.True(t, present, "payload should be present") {
			return
		}
		// Read payload
		data, err := payloadStore.ReadPayload(hash)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, payload, data)
	})
}

// graphF creates the following graph:
//..................A
//................/  \
//...............B    C
//...............\   / \
//.................D    E
//.......................\
//........................F
func graphF(creator func(t *testing.T) DAG, t *testing.T) (DAG, []Document) {
	graph := creator(t)
	A := CreateTestDocument(0)
	B := CreateTestDocument(1, A.Ref())
	C := CreateTestDocument(2, A.Ref())
	D := CreateTestDocument(3, B.Ref(), C.Ref())
	E := CreateTestDocument(4, C.Ref())
	F := CreateTestDocument(5, E.Ref())
	docs := []Document{A, B, C, D, E, F}
	graph.Add(docs...)
	return graph, docs
}
