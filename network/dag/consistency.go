/*
 * Copyright (C) 2023 Nuts community
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
	"context"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
	"sync"
	"time"
)

type circuit int

const (
	circuitGreen circuit = iota
	circuitYellow
	circuitRed
)

// xorTreeRepair is responsible for repairing the XOR tree. Its loop is triggered when the network layer detects differences in XOR values with all other nodes.
// It will loop over all pages of the XOR tree and recalculates the XOR value with the transactions in the database.
// This repair is needed because current networks have nodes that have a wrong XOR value. How this happens is not yet known, it could be due to DB failures of due to failures in older versions.
// The fact is that we can fix the state relatively easy.
// The loop checks a page (512 LC values) per 10 seconds and continues looping until the network layer signals all is ok again.
type xorTreeRepair struct {
	ctx          context.Context
	cancel       context.CancelFunc
	ticker       *time.Ticker
	currentPage  uint32
	state        *state
	circuitState circuit
	mutex        sync.Mutex
}

func newXorTreeRepair(state *state) *xorTreeRepair {
	return &xorTreeRepair{
		state:  state,
		ticker: time.NewTicker(10 * time.Second),
	}
}

func (f *xorTreeRepair) start() {
	f.ctx, f.cancel = context.WithCancel(context.Background())
	go f.loop()
}

func (f *xorTreeRepair) shutdown() {
	if f.cancel != nil {
		f.cancel()
	}
}

func (f *xorTreeRepair) loop() {
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-f.ticker.C:
			f.checkPage()
		}
	}
}

func (f *xorTreeRepair) checkPage() {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// ignore run if circuit is not red
	if f.circuitState < circuitRed {
		return
	}

	currentLC := f.state.lamportClockHigh.Load()
	lcStart := f.currentPage * PageSize
	lcEnd := lcStart + PageSize

	// initialize an XOR tree
	calculatedXorTree := tree.New(tree.NewXor(), PageSize)

	// acquire global lock
	err := f.state.graph.db.Write(context.Background(), func(txn stoabs.WriteTx) error {
		txs, err := f.state.graph.findBetweenLC(txn, lcStart, lcEnd)
		if err != nil {
			return err
		}
		for _, tx := range txs {
			calculatedXorTree.Insert(tx.Ref(), tx.Clock())
		}

		// Get XOR leaf from current XOR tree
		xorTillEnd, _ := f.state.xorTree.getZeroTo(lcEnd - 1)
		if lcStart != 0 {
			xorTillStart, _ := f.state.xorTree.getZeroTo(lcStart - 1)
			_ = xorTillEnd.Subtract(xorTillStart)
		}

		// Subtract the calculated tree, should be empty if the trees are equal
		_ = xorTillEnd.Subtract(calculatedXorTree.Root())
		if !xorTillEnd.Empty() {
			// it's not empty, so replace the leaf in the current XOR tree with the calculated one
			err = f.state.xorTree.tree.Replace(lcStart, calculatedXorTree.Root())
			if err != nil {
				return err
			}
			log.Logger().Warnf("detected XOR tree mismatch for page %d, fixed using recalculated values", f.currentPage)
		}

		// Now we do the same for the IBLT tree as stated in
		// https://github.com/nuts-foundation/nuts-node/issues/2295
		// we skip the iblt tree for now, since the chance for it to become corrupt is incredibly low.
		// there can only be a problem with duplicate entries, not with missing entries.
		// the xor tree already has an effect when it's missing entries.
		// fixing the iblt tree is a copy of the code above (but with ibltTree instead of xorTree).

		return nil
	})
	if err != nil {
		log.Logger().Warnf("failed to run xorTreeRepair check: %s", err)
	}

	if lcEnd > currentLC {
		// start over when end is reached for next run
		f.currentPage = 0
	} else {
		// increment page so on the next round we check a different page.
		f.currentPage++
	}
}

func (f *xorTreeRepair) stateOK() {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.circuitState = circuitGreen
	f.currentPage = 0
}

func (f *xorTreeRepair) incrementCount() {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.circuitState++
}
