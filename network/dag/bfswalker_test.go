package dag

import (
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestBFSWalkerAlgorithm(t *testing.T) {
	t.Run("ok - walk graph F", func(t *testing.T) {
		graph := CreateDAG(t)
		graph.Add(graphF()...)
		visitor := trackingVisitor{}

		root, _ := graph.Root()
		err := graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Regexp(t, "^0, (1, 2|2, 1), (3, 4|4, 3), 5$", visitor.JoinRefsAsString())
	})

	t.Run("ok - walk graph G", func(t *testing.T) {
		graph := CreateDAG(t)
		graph.Add(graphG()...)
		visitor := trackingVisitor{}
		root, _ := graph.Root()
		graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)

		assert.Regexp(t, "^0, (1, 2|2, 1), (3, 4|4, 3), 5, 6$", visitor.JoinRefsAsString())
	})

	t.Run("ok - walk graph F, C is missing", func(t *testing.T) {
		//..................A
		//................/  \
		//...............B    C (missing)
		//...............\   / \
		//.................D    E
		//.......................\
		//........................F
		graph := CreateDAG(t)
		visitor := trackingVisitor{}
		docs := graphF()
		graph.Add(docs[0], docs[1], docs[3], docs[4], docs[5])

		root, _ := graph.Root()
		graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)

		assert.Equal(t, "0, 1", visitor.JoinRefsAsString())
	})

	t.Run("ok - walk graph G, C resume point", func(t *testing.T) {
		//..................A
		//................/  \
		//...............B    C (resume point)
		//...............\   / \
		//.................D    E
		//.......................\
		//........................F
		graph := CreateDAG(t)
		docs := graphG()
		graph.Add(docs...)
		docC := docs[2]

		root, _ := graph.Root()
		walker := NewBFSWalkerAlgorithm()
		visitorBeforeResume := trackingVisitor{}
		graph.Walk(walker, func(transaction Transaction) bool {
			if transaction.Ref().Equals(docC.Ref()) {
				return false
			}
			return visitorBeforeResume.Accept(transaction)
		}, root)

		// Make sure it breaks at C, having processed A and B
		assert.Equal(t, "0, 1", visitorBeforeResume.JoinRefsAsString())

		// Now resume, not breaking at C
		visitorAfterResume := trackingVisitor{}
		graph.Walk(walker, visitorAfterResume.Accept, hash.EmptyHash())

		// Make sure it resumes at C, then processes E, D and F.
		refs := visitorAfterResume.JoinRefsAsString()
		assert.Regexp(t, "^2, (4, 3|3, 4), 5, 6$", refs)

		// Make sure DAG isn't revisited after walk is invoked when the complete DAG has been walked already
		visitorAfterCompleteWalk := trackingVisitor{}
		graph.Walk(walker, visitorAfterResume.Accept, root)
		assert.Equal(t, "", visitorAfterCompleteWalk.JoinRefsAsString())
	})

	t.Run("ok - empty graph", func(t *testing.T) {
		graph := CreateDAG(t)
		visitor := trackingVisitor{}

		root, _ := graph.Root()
		err := graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.transactions)
	})
}
