package dag

import (
	"context"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

func TestBFSWalkerAlgorithm(t *testing.T) {
	t.Run("ok - walk graph F", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		graph.Add(ctx, graphF()...)
		visitor := trackingVisitor{}

		root, _ := graph.Root(ctx)
		err := graph.Walk(ctx, NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Regexp(t, "^0, (1, 2|2, 1), (3, 4|4, 3), 5$", visitor.JoinRefsAsString())
	})

	t.Run("ok - walk graph G", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		graph.Add(ctx, graphG()...)
		visitor := trackingVisitor{}
		root, _ := graph.Root(ctx)
		graph.Walk(ctx, NewBFSWalkerAlgorithm(), visitor.Accept, root)

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
		ctx := context.Background()
		graph := CreateDAG(t)
		visitor := trackingVisitor{}
		docs := graphF()
		graph.Add(ctx, docs[0], docs[1], docs[3], docs[4], docs[5])

		root, _ := graph.Root(ctx)
		graph.Walk(ctx, NewBFSWalkerAlgorithm(), visitor.Accept, root)

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
		ctx := context.Background()
		graph := CreateDAG(t)
		docs := graphG()
		graph.Add(ctx, docs...)
		docC := docs[2]

		root, _ := graph.Root(ctx)
		walker := NewBFSWalkerAlgorithm()
		visitorBeforeResume := trackingVisitor{}
		graph.Walk(ctx, walker, func(ctx context.Context, transaction Transaction) bool {
			if transaction.Ref().Equals(docC.Ref()) {
				return false
			}
			return visitorBeforeResume.Accept(ctx, transaction)
		}, root)

		// Make sure it breaks at C, having processed A and B
		assert.Equal(t, "0, 1", visitorBeforeResume.JoinRefsAsString())

		// Now resume, not breaking at C
		visitorAfterResume := trackingVisitor{}
		graph.Walk(ctx, walker, visitorAfterResume.Accept, hash.EmptyHash())

		// Make sure it resumes at C, then processes E, D and F.
		refs := visitorAfterResume.JoinRefsAsString()
		assert.Regexp(t, "^2, (4, 3|3, 4), 5, 6$", refs)

		// Make sure DAG isn't revisited after walk is invoked when the complete DAG has been walked already
		visitorAfterCompleteWalk := trackingVisitor{}
		graph.Walk(ctx, walker, visitorAfterResume.Accept, root)
		assert.Equal(t, "", visitorAfterCompleteWalk.JoinRefsAsString())
	})

	t.Run("ok - empty graph", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		visitor := trackingVisitor{}

		root, _ := graph.Root(ctx)
		err := graph.Walk(ctx, NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.transactions)
	})
}
