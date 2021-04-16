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

package proto

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"math"
	"strings"
	"sync"
	"time"
)

const numberOfBlocks = 3

// NewDAGBlocks creates a new tracking DAGBlocks structure.
func NewDAGBlocks() DAGBlocks {
	result := &trackingDAGBlocks{make([]*block, numberOfBlocks)}
	for i := 0; i < len(result.blocks); i++ {
		result.blocks[i] = &block{heads: map[hash.SHA256Hash]*head{}}
	}
	result.updateTimestamps(time.Now())
	return result
}

// MutexWrapDAGBlocks wraps a DAGBlocks in a DAGBlocks implementation that secures access with a mutex,
// allowing concurrent access.
func MutexWrapDAGBlocks(underlying DAGBlocks) DAGBlocks {
	return &muxDAGBlocks{
		Underlying: underlying,
		mux:        &sync.Mutex{},
	}
}

// XORHeads calculates a hash over all heads using bitwise XOR.
func (b DAGBlock) XORHeads() hash.SHA256Hash {
	var result hash.SHA256Hash
	if len(b.Heads) == 0 {
		return result
	}
	result = b.Heads[0]
	for i := 1; i < len(b.Heads); i++ {
		xor(&result, result, b.Heads[i])
	}
	return result
}

// trackingDAGBlocks is a DAGBlocks implementation tracks the DAG block heads in a memory friendly way. It works by
// storing the known heads of a block and the distance (in blocks) to the next TX (by which it is prev'd) so it can be
// unmarked as head when the next TX is moved into the historic block. When midnight passes (and thus blocks change)
// it shifts all TXs one block to the left, ultimately into the leftmost historic block.
type trackingDAGBlocks struct {
	blocks []*block
}

type muxDAGBlocks struct {
	Underlying DAGBlocks
	mux        *sync.Mutex
}

func (m muxDAGBlocks) String() string {
	m.mux.Lock()
	defer m.mux.Unlock()
	return m.Underlying.String()
}

func (m muxDAGBlocks) Get() []DAGBlock {
	m.mux.Lock()
	defer m.mux.Unlock()
	return m.Underlying.Get()
}

func (m muxDAGBlocks) AddTransaction(tx dag.SubscriberTransaction, payload []byte) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	return m.Underlying.AddTransaction(tx, payload)
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

// heads calculates the block heads, without updating the structure first. Only for internal use and testing.
func (blx *trackingDAGBlocks) heads() []DAGBlock {
	result := make([]DAGBlock, 0)
	for blockNum, currBlock := range blx.blocks {
		resultBlock := DAGBlock{Start: currBlock.start}
		for ref, _ := range currBlock.heads {
			if blockNum < len(blx.blocks) {
				resultBlock.Heads = append(resultBlock.Heads, ref)
			}
		}
		result = append(result, resultBlock)
	}
	return result
}

// Heads returns the block heads.
func (blx *trackingDAGBlocks) Get() []DAGBlock {
	blx.update(time.Now())
	return blx.heads()
}

// AddTransaction adds a transaction to the DAG blocks structure. It MUST with the transactions in order, so it's
// typically called using a sequential DAG subscriber. So given TXs `A <- B <- [C, D]` call order is A, B, C, D (or A, B, D, C).
func (blx *trackingDAGBlocks) AddTransaction(tx dag.SubscriberTransaction, _ []byte) error {
	blx.update(time.Now())
	// Determine block the TX is part of
	blockIdx := len(blx.blocks) - 1
	for i := 0; i < len(blx.blocks)-1; i++ {
		// Lower blocks are earlier, so when the TXs time is before the start time of the next block, this is the block
		// the TX is part of.
		if tx.SigningTime().Before(blx.blocks[i+1].start) {
			blockIdx = i
			break
		}
	}
	txBlock := blx.blocks[blockIdx]
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
		distance:    math.MaxInt64,
		signingTime: tx.SigningTime(),
		blockDate:   txBlockDate,
	}
	// Find prevs is this TX that are currently heads in the previous blocks and set the shortest distance. When the blocks
	// are updated and the "next TX's" block distance reaches zero, that means the next TX is in the same block and thus
	// the head isn't a head any more.
	for i := 0; i <= blockIdx; i++ {
		for _, currPrev := range tx.Previous() {
			if head, ok := blx.blocks[i].heads[currPrev]; ok {
				newDistance := int(txBlockDate.Sub(head.blockDate).Hours() / 24)
				if newDistance < head.distance {
					head.distance = newDistance
				}
			}
		}
	}
	return nil
}

// update first updates the timestamps on the blocks and then redistributes the transactions into the correct blocks.
// It must be called before any interaction (reading the heads, adding a transaction) with the structure. Callers must
// make sure it's never called with an older timestamp (a timestamp which lies before the timestamp it was last called with).
func (blx *trackingDAGBlocks) update(now time.Time) {
	if !blx.updateTimestamps(now) {
		// Blocks timestamps not updated, nothing to do.
		return
	}
	// Block timestamps were updated, now move the TXs to their new blocks. This will generally mean shift 1 block to the
	// left, except for TXs with are already in the leftmost block and TXs that are in the current block and remain there
	// (because the signing time lies in the future).
	numBlocks := len(blx.blocks)
	for i := 0; i < numBlocks; i++ {
		curr := blx.blocks[i]
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
		// Move TXs in the block to the right to the this block, unless the TX's signing time is in the future
		// (which can actually only be the case for the current day's block).
		if i < numBlocks-1 {
			next := blx.blocks[i+1]
			for ref, head := range next.heads {
				if head.signingTime.Before(next.start) {
					curr.heads[ref] = head
					delete(next.heads, ref)
				}
			}
		}
	}
}

// updateTimestamps updates the timestamps of the blocks using the given time. If there's already transactions in the
// blocks they must be redistributed (so they end up in the correct block) after this function has been called.
func (blx *trackingDAGBlocks) updateTimestamps(now time.Time) bool {
	t := startOfDay(now)
	changed := false
	for idx, currBlock := range blx.blocks {
		if idx == 0 {
			continue
		}
		newDate := t.AddDate(0, 0, idx-len(blx.blocks)+1)
		if !newDate.Equal(currBlock.start) {
			currBlock.start = newDate
			changed = true
		}
	}
	return changed
}

func (blx trackingDAGBlocks) String() string {
	lines := make([]string, len(blx.blocks))
	for i := 0; i < len(lines); i++ {
		lines[i] = fmt.Sprintf("  [%d] %v", i, *blx.blocks[i])
	}
	return fmt.Sprintf("blocks:\n%s", strings.Join(lines, "\n"))
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

func startOfDay(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

func xor(dest *hash.SHA256Hash, left, right hash.SHA256Hash) {
	for i := 0; i < len(left); i++ {
		dest[i] = left[i] ^ right[i]
	}
}
