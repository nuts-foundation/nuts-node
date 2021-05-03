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

// trackingDAGBlocks is a dagBlocks implementation tracks the DAG block heads in a memory friendly way.
// It works by storing the known heads of a block and the distance (in blocks) to the next TX (by which it is prev'd),
// so it can be unmarked as head when the next TX is moved into the historic block.
// When midnight passes (and thus blocks change) it shifts all TXs one block to the left, ultimately into the leftmost historic block.
type trackingDAGBlocks struct {
	blocks []*blockTracker
	mux    *sync.Mutex
}

// dagBlocks defines the API for algorithms that determine the head transactions for DAG blocks.
type dagBlocks interface {
	// String returns the state of the algorithm as string.
	String() string
	// get returns a slice containing the DAG blocks left-to-right (historic block at [0], current block at [len(blocks) - 1]).
	get() []dagBlock
	// addTransaction adds a transaction to the DAG blocks structure. It MUST be called in actual transactions order,
	// So given TXs `A <- B <- [C, D]` call order is A, B, C, D (or A, B, D, C).
	// It will typically be called using a sequential DAG subscriber.
	addTransaction(tx dag.Transaction, _ []byte) error
}

// newDAGBlocks creates a new tracking dagBlocks structure.
func newDAGBlocks() dagBlocks {
	result := &trackingDAGBlocks{
		blocks: make([]*blockTracker, numberOfBlocks),
		mux:    &sync.Mutex{},
	}
	for i := 0; i < len(result.blocks); i++ {
		result.blocks[i] = &blockTracker{heads: map[hash.SHA256Hash]*head{}}
	}
	result.internalUpdateTimestamps(time.Now())
	return result
}

// dagBlock is a DAG block.
type dagBlock struct {
	// start contains the start time of the block.
	start time.Time
	// heads contains the heads of the block.
	heads []hash.SHA256Hash
}

// xor calculates a hash over all heads using bitwise xor.
func (b dagBlock) xor() hash.SHA256Hash {
	var result hash.SHA256Hash
	multiXOR(&result, b.heads...)
	return result
}

type blockTracker struct {
	start time.Time
	// key: tx ref, value: distance (in blocks) of the next TX
	heads map[hash.SHA256Hash]*head
}

type head struct {
	// distance contains number of blocks to the next TX that refers to this TX as 'prev'. If the next TX is in the next
	// block, distance will be 1. If `distance is 0, it means the next TX is in the same block. It is initialized
	// to math.MaxInt64, meaning no next TX.
	distance    int32
	signingTime time.Time
	// blockDate contains the signing time at start of the block
	blockDate time.Time
}

// internalGet calculates the block heads, without updating the structure first. Only for internal use and testing.
func (blx *trackingDAGBlocks) internalGet() []dagBlock {
	result := make([]dagBlock, 0)
	for blockNum, currBlock := range blx.blocks {
		resultBlock := dagBlock{start: currBlock.start}
		for ref := range currBlock.heads {
			if blockNum < len(blx.blocks) {
				resultBlock.heads = append(resultBlock.heads, ref)
			}
		}
		result = append(result, resultBlock)
	}
	return result
}

// get returns the current block heads. Successive calls might return a different result since they're distributed in relation to the current day.
func (blx *trackingDAGBlocks) get() []dagBlock {
	blx.mux.Lock()
	defer blx.mux.Unlock()
	blx.internalUpdate(time.Now())
	return blx.internalGet()
}

// AddTransaction adds a transaction to the DAG blocks structure. It MUST be called for transactions in order,
// so it's typically called using a sequential DAG subscriber.
// So given TXs `A <- B <- [C, D]` call order is A, B, C, D (or A, B, D, C).
func (blx *trackingDAGBlocks) addTransaction(tx dag.Transaction, _ []byte) error {
	blx.mux.Lock()
	defer blx.mux.Unlock()
	blx.internalUpdate(time.Now())
	blx.internalAddTransaction(tx)
	return nil
}

func (blx *trackingDAGBlocks) internalAddTransaction(tx dag.Transaction) {
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
	// the current TX will be the new head. So we 'un-head' all prevs and mark the current TX as head.
	// This works as long as this func is called with TXs in order.
	txBlockDate := startOfDay(tx.SigningTime())
	for _, prev := range tx.Previous() {
		if prevTX, ok := txBlock.heads[prev]; ok {
			// But not if the signing time of the tx would put it in a future block,
			// which can be the case when TXs with future timestamps are added to today's block.
			if !txBlockDate.After(prevTX.blockDate) {
				delete(txBlock.heads, prev)
			}
		}
	}
	txBlock.heads[tx.Ref()] = &head{
		distance:    math.MaxInt32,
		signingTime: tx.SigningTime(),
		blockDate:   txBlockDate,
	}
	// Find prevs is this TX that are currently heads in the previous blocks and set the shortest distance.
	// When the blocks are updated and the "next TX's" block distance reaches zero,
	// that means the next TX is in the same block and thus the head isn't a head any more.
	for i := 0; i <= blockIdx; i++ {
		for _, currPrev := range tx.Previous() {
			if head, ok := blx.blocks[i].heads[currPrev]; ok {
				newDistance := int32(txBlockDate.Sub(head.blockDate).Hours() / 24)
				if newDistance < head.distance {
					head.distance = newDistance
				}
			}
		}
	}
}

// internalUpdate first updates the timestamps on the blocks and then redistributes the transactions into the correct blocks.
// It must be called before any interaction (reading the heads, adding a transaction) with the structure.
// Callers must make sure it's never called with an older timestamp (a timestamp which lies before the timestamp it was last called with).
func (blx *trackingDAGBlocks) internalUpdate(now time.Time) {
	if !blx.internalUpdateTimestamps(now) {
		// Day didn't pass since last call so block timestamps are not updated -> nothing to do.
		return
	}
	// Block timestamps were updated, now move the TXs to their new blocks. This will generally mean shift 1 block to the left,
	// except for TXs with are already in the leftmost block and TXs that are in the current block and remain there
	// (because the signing time lies in the future).
	numBlocks := len(blx.blocks)
	for i := 0; i < numBlocks; i++ {
		curr := blx.blocks[i]
		if i == 0 {
			updateTXBlockDistances(curr)
		}
		if i < numBlocks-1 {
			next := blx.blocks[i+1]
			blx.leftShiftTXs(curr, next)
		}
	}
}

// leftShiftTXs shifts the transactions in the right block to the left block,
// but only if the signing time puts it into the left block (which can be the case for TXs in current day's block).
func (blx *trackingDAGBlocks) leftShiftTXs(left *blockTracker, right *blockTracker) {
	for ref, head := range right.heads {
		if head.signingTime.Before(right.start) {
			left.heads[ref] = head
			delete(right.heads, ref)
		}
	}
}

// updateTXBlockDistances updates the historic block:
// - decrement `distance`
// - when `distance` reaches zero, the unmark the TX as block head
func updateTXBlockDistances(historicBlock *blockTracker) {
	for ref, head := range historicBlock.heads {
		if head.distance != math.MaxInt32 {
			head.distance--
			if head.distance == 0 {
				// Next TX of the head TX now falls within this block, so unmark it as block head
				delete(historicBlock.heads, ref)
			}
		}
	}
}

// internalUpdateTimestamps updates the timestamps of the blocks using the given time.
// If there's already transactions in the blocks they must be redistributed (so they end up in the correct block) after this function has been called.
func (blx *trackingDAGBlocks) internalUpdateTimestamps(now time.Time) bool {
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

func (b blockTracker) String() string {
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

func multiXOR(dest *hash.SHA256Hash, hashes ...hash.SHA256Hash) {
	if len(hashes) == 0 {
		return
	}
	*dest = hashes[0]
	for i := 1; i < len(hashes); i++ {
		xor(dest, *dest, hashes[i])
	}
}
