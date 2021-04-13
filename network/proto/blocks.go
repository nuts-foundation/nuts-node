package proto

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"math"
	"strings"
	"time"
)

func NewDAGBlocks(numberOfBlocks int) *DAGBlocks {
	result := &DAGBlocks{make([]*block, numberOfBlocks)}
	for i := 0; i < len(result.blocks); i++ {
		result.blocks[i] = &block{heads: map[hash.SHA256Hash]*head{}}
	}
	result.updateBlockTimestamps(time.Now())
	return result
}

type DAGBlocks struct {
	blocks []*block
}

func (blox DAGBlocks) String() string {
	lines := make([]string, len(blox.blocks))
	for i := 0; i < len(lines); i++ {
		lines[i] = fmt.Sprintf("  [%d] %v", i, *blox.blocks[i])
	}
	return fmt.Sprintf("blocks:\n%s", strings.Join(lines, "\n"))
}

func (blox *DAGBlocks) heads() [][]hash.SHA256Hash {
	result := make([][]hash.SHA256Hash, 0)
	for blockNum, b := range blox.blocks {
		var heads []hash.SHA256Hash
		for ref, _ := range b.heads {
			if blockNum < len(blox.blocks) {
				heads = append(heads, ref)
			}
		}
		result = append(result, heads)
	}
	return result
}

func (blox *DAGBlocks) Heads() [][]hash.SHA256Hash {
	blox.update(time.Now())
	return blox.heads()
}

type block struct {
	start time.Time
	// key: tx ref, value: distance (in blocks) of the next TX
	heads map[hash.SHA256Hash]*head
}

type head struct {
	distance    int
	signingTime time.Time
	// blockDate contains the signing time at start of the block
	blockDate time.Time
}

func (b block) String() string {
	if len(b.heads) > 0 {
		items := make([]string, 0, len(b.heads))
		for ref, head := range b.heads {
			items = append(items, fmt.Sprintf("%s:%d", ref, head.distance))
		}
		return strings.Join(items, ", ")
	}
	return "(empty)"
}

// AddTransaction adds a transaction to the DAG blocks structure. It MUST with the transactions in order, so it's
// typically called using a sequential DAG subscriber. So given TXs `A <- B <- [C, D]` call order is A, B, C, D (or A, B, D, C).
func (blox *DAGBlocks) AddTransaction(tx dag.SubscriberTransaction, _ []byte) error {
	blox.update(time.Now())
	// Determine block the TX is part of
	blockIdx := len(blox.blocks) - 1
	for i := 0; i < len(blox.blocks)-1; i++ {
		// Lower blocks are earlier, so when the TXs time is before the start time of the next block, this is the block
		// the TX is part of.
		if tx.SigningTime().Before(blox.blocks[i+1].start) {
			blockIdx = i
			break
		}
	}
	txBlock := blox.blocks[blockIdx]
	// Prevs of this TX in this block were previously heads (prev'd by another branch within this block) but now
	// the current TX will be the new head. So we 'un-head' all prevs and mark the current TX as head. This works as long
	// as this func is called with TXs in order.
	txBlockDate := startOfDay(tx.SigningTime())
	for _, prev := range tx.Previous() {
		if prevTX, ok := txBlock.heads[prev]; ok {
			// But not if this the signing time of the tx would put it in a future block, which can be the case
			// when tx's with future timestamps are added in today's block
			if !txBlockDate.After(prevTX.blockDate) {
				delete(txBlock.heads, prev)
			}
		}
	}
	txBlock.heads[tx.Ref()] = &head{
		distance: math.MaxInt64,
		signingTime: tx.SigningTime(),
		blockDate: txBlockDate,
	}
	// Find prevs is this TX that are currently heads in the previous blocks and set the shortest distance. When the blocks
	// are updated and the "next TX's" block distance reaches zero, that means the next TX is in the same block and thus
	// the head isn't a head any more.
	for i := 0; i <= blockIdx; i++ {
		for _, currPrev := range tx.Previous() {
			if head, ok := blox.blocks[i].heads[currPrev]; ok {
				newDistance := int(txBlockDate.Sub(head.blockDate).Hours() / 24)
				if newDistance < head.distance {
					head.distance = newDistance
				}
			}
		}
	}
	return nil
}

// getBlocks returns a slice containing the heads of the DAG as blocks. The entry at index 0 contains the current block,
// the entry at 1 contains yesterday's block, etc. The last entry is special because it contains all heads leading up
// and including that block.
func (blox *DAGBlocks) update(now time.Time) {
	numBlocks := len(blox.blocks)

	if !blox.updateBlockTimestamps(now) {
		return
	}

	// Block timestamps were updated, now move the TXs to their new blocks. This will generally mean shift 1 block to the
	// left, except for TXs with are already in the leftmost block and TXs that are in the current block and remain there
	// (because the signing time lies in the future).
	for i := 0; i < numBlocks; i++ {
		curr := blox.blocks[i]
		// For the left-most block:
		//  - decrement `distance`
		//  - when `distance` reaches zero, the unmark the TX as block head
		if i == 0 {
			for ref, head := range curr.heads {
				if head.distance != math.MaxInt64 {
					head.distance--
					if head.distance == 0 {
						// Next TX of the head TX now falls within this block, so unmark it as block head
						delete(curr.heads, ref)
					}
				}
			}
		}
		if i < numBlocks-1 {
			next := blox.blocks[i+1]
			for ref, head := range next.heads {
				if head.signingTime.Before(next.start) {
					curr.heads[ref] = head
					delete(next.heads, ref)
				}
			}
		}
	}
}

func (blox *DAGBlocks) updateBlockTimestamps(now time.Time) bool {
	t := startOfDay(now)
	changed := false
	for idx, currBlock := range blox.blocks {
		if idx == 0 {
			continue
		}
		newDate := t.AddDate(0, 0, idx-len(blox.blocks)+1)
		if !newDate.Equal(currBlock.start) {
			currBlock.start = newDate
			changed = true
		}
	}
	return changed
}

func startOfDay(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}
