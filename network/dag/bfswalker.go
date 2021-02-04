package dag

import (
	"container/list"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"sort"
)

// bfsWalkerAlgorithm walks the DAG using the Breadth-First-Search (BFS) as described by Anany Levitin in "The Design & Analysis of Algorithms".
// It visits the whole tree level for level (breadth first vs depth first). It works by taking a node from queue and
// then adds the node's children (downward edges) to the queue. It starts by adding the root node to the queue and
// loops over the queue until empty, meaning all nodes reachable from the root node have been visited. Since our
// DAG contains merges (two parents referring to the same child node) we also keep a map to avoid visiting a
// merger node twice.
//
// This also means we have to make sure we don't visit the merger node before all of its previous nodes have been
// visited, which BFS doesn't account for. If that happens we skip the node without marking it as visited,
// so it will be visited again when the unvisited previous node is visited, which re-adds the merger node to the queue.
//
// In addition, when the visitor stops the walking (by returning false), it breaks off the walking for that specific branch of the DAG.
//
// It is also stateful: it remembers which documents were visited and where to resume walking next time it is invoked.
// This is useful for subscriptions: the first time the DAG is walked all documents are processed, keeping track of
// which branches couldn't be processed (payload might be missing, so it has to be processed layer). Next time the
// walker is invoked it starts walking at the documents in the `resumeAt` list and ultimately honoring the `startAt`
// hash.
type bfsWalkerAlgorithm struct {
	resumeAt         *list.List
	visitedDocuments map[hash.SHA256Hash]bool
}

// NewBFSWalkerAlgorithm creates a new bfsWalkerAlgorithm.
func NewBFSWalkerAlgorithm() WalkerAlgorithm {
	return &bfsWalkerAlgorithm{
		resumeAt:         list.New(),
		visitedDocuments: map[hash.SHA256Hash]bool{},
	}
}

func (w bfsWalkerAlgorithm) walk(visitor Visitor, startAt hash.SHA256Hash, getFn func(hash.SHA256Hash) (Document, error), nextsFn func(hash.SHA256Hash) ([]hash.SHA256Hash, error)) error {
	queue := list.New()
	queue.PushFrontList(w.resumeAt)
	if !startAt.Empty() {
		queue.PushBack(startAt)
	}
	w.resumeAt.Init()
ProcessQueueLoop:
	for queue.Len() > 0 {
		// Pop first element of queue
		front := queue.Front()
		queue.Remove(front)
		currentRef := front.Value.(hash.SHA256Hash)

		// Make sure we haven't already visited this node
		if _, visited := w.visitedDocuments[currentRef]; visited {
			continue
		}

		// Make sure all prevs have been visited. Otherwise just continue, it will be re-added to the queue when the
		// unvisited prev node is visited and re-adds this node to the processing queue.
		currentDocument, err := getFn(currentRef)
		if err != nil {
			return err
		}

		for _, prev := range currentDocument.Previous() {
			if _, visited := w.visitedDocuments[prev]; !visited {
				continue ProcessQueueLoop
			}
		}

		// Visit the node
		if !visitor(currentDocument) {
			// Visitor returned false, so stop processing this branch. Resume at later point.
			w.resumeAt.PushBack(currentRef)
			continue
		}

		// Add child nodes to processing queue
		// Processing order of nodes on the same level doesn't really matter for correctness of the DAG travel
		// but it makes testing easier.
		if nexts, err := nextsFn(currentRef); err != nil {
			return err
		} else if nexts != nil {
			sortedEdges := make([]hash.SHA256Hash, 0, len(nexts))
			for _, nextNode := range nexts {
				sortedEdges = append(sortedEdges, nextNode)
			}
			sort.Slice(sortedEdges, func(i, j int) bool {
				return sortedEdges[i].Compare(sortedEdges[j]) < 0
			})
			for _, nextNode := range sortedEdges {
				queue.PushBack(nextNode)
			}
		}

		// Mark this node as visited
		w.visitedDocuments[currentRef] = true
	}
	return nil
}
