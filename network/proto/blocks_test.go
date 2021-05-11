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
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

type testCase struct {
	name string
	// txs contains the transactions to be added
	txs []tx
	// heads contains the expected block head transactions. They're specified by transaction name as specified in `txs`.
	// The heads expected in a block are comma separated, so `A, B, C` means 3 blocks with A in the historic block,
	// B in the next block, C in the current block. If there should be multiple heads they can be specified separated
	// with a space, for example `A B, , C` (historic block=A and B, next one=empty, current=C).
	// Every entry in the slice represents a "day" passed. If there's 2 entries, it emulates the passing of 1 day.
	// If there's 3 entries, it emulates the passing of 2 days. The first entry is the initial state.
	heads []string
}

type tx struct {
	name  string
	time  int
	prevs []string
}

func noPrevs() []string {
	return []string{}
}

func prev(name string) []string {
	return []string{name}
}

// Test cases visualized with https://asciiflow.com/
func testCases() []testCase {
	return []testCase{
		/*
			      │        │
			┌───┐ │  ┌───┐ │  ┌───┐
			│ A ├─┼─►│ B ├─┼─►│ C │
			└───┘ │  └───┘ │  └───┘
			      │        │
		*/
		{
			name: "simple",
			txs: []tx{
				tx{"A", 0, noPrevs()},
				tx{"B", 1, prev("A")},
				tx{"C", 2, prev("B")},
			},
			heads: []string{
				"A, B, C",
				"B, C",
				"C",
			},
		},
		/*
			              │        │
			┌───┐   ┌───┐ │  ┌───┐ │ ┌───┐
			│ A ├──►│ B ├─┼─►│ C ├─┼►│ D │
			└───┘   └───┘ │  └───┘ │ └───┘
			              │        │
		*/
		{
			name: "2 transactions in historic block",
			txs: []tx{
				tx{"A", -20, noPrevs()},
				tx{"B", -10, prev("A")},
				tx{"C", 1, prev("B")},
				tx{"D", 2, prev("C")},
			},
			heads: []string{
				"B, C, D",
				"C, D",
				"D",
			},
		},
		/*
			      │        │
			┌───┐ │  ┌───┐ │  ┌───┐  ┌───┐
			│ A ├─┼─►│ B ├─┼─►│ C ├─►│ D │
			└───┘ │  └───┘ │  └───┘  └───┘
			      │        │
		*/
		{
			name: "simple + D",
			txs: []tx{
				tx{"A", 0, noPrevs()},
				tx{"B", 1, prev("A")},
				tx{"C", 2, prev("B")},
				tx{"D", 2, prev("C")},
			},
			heads: []string{
				"A, B, D",
				"B, D",
				"D",
			},
		},
		/*
			      │        │
			┌───┐ │  ┌───┐ │  ┌───┐
			│ A ├─┼─►│ B ├─┼─►│ C │
			└─┬─┘ │  └───┘ │  └───┘
			  │   │        │
			  │   │        │  ┌───┐
			  └───┼────────┼─►│ D │
			      │        │  └───┘
		*/
		{
			name: "long branch from history",
			txs: []tx{
				tx{"A", 0, noPrevs()},
				tx{"B", 1, prev("A")},
				tx{"C", 2, prev("B")},
				tx{"D", 2, prev("A")},
			},
			heads: []string{
				"A, B, C D",
				"B, C D",
				"C D",
			},
		},
		/*
			      │        │
			┌───┐ │  ┌───┐ │  ┌───┐  ┌───┐
			│ A ├─┼─►│ B ├─┼─►│ C ├─►│ D │
			└───┘ │  └─┬─┘ │  └───┘  └───┘
			      │    │   │
			      │  ┌─▼─┐ │
			      │  │ E │ │
			      │  └───┘ │
		*/
		{
			name: "simple + D + branch",
			txs: []tx{
				tx{"A", 0, noPrevs()},
				tx{"B", 1, prev("A")},
				tx{"C", 2, prev("B")},
				tx{"D", 2, prev("C")},
				tx{"E", 1, prev("B")},
			},
			heads: []string{
				"A, E, D",
				"E, D",
				"D E",
			},
		},
	}
}

func TestBlocks(t *testing.T) {
	for _, tc := range testCases() {
		t.Run(tc.name, func(t *testing.T) {
			blocks := newDAGBlocks().(*trackingDAGBlocks)
			txs := make(map[string]dag.Transaction, 0)
			oldestTXAge := 0
			for _, currTX := range tc.txs {
				// Resolve prevs
				prevs := make([]hash.SHA256Hash, 0)
				for _, prev := range currTX.prevs {
					if _, ok := txs[prev]; !ok {
						t.Fatalf("prev not found: %s", prev)
					}
					prevs = append(prevs, txs[prev].Ref())
				}
				// Make TX
				tx := testTX{
					data: []byte(currTX.name),
					prev: prevs,
					sigt: time.Now().AddDate(0, 0, currTX.time-numberOfBlocks+1),
				}
				if currTX.time > oldestTXAge {
					oldestTXAge = currTX.time
				}
				txs[currTX.name] = tx
				err := blocks.addTransaction(&tx, nil)
				if !assert.NoError(t, err) {
					return
				}
			}
			println(blocks.String())
			for dayNum := 0; dayNum < oldestTXAge+1; dayNum++ {
				// Assert blocks
				expectedBlocks := strings.Split(tc.heads[dayNum], ", ")
				actualBlocks := blocks.internalGet()
				for blockNum, blockHeadsConcatted := range expectedBlocks {
					expectedHeads := strings.Split(strings.TrimSpace(blockHeadsConcatted), " ")
					actualHeads := make(map[hash.SHA256Hash]bool, 0)
					for _, curr := range actualBlocks[blockNum].heads {
						actualHeads[curr] = true
					}
					for _, blockHead := range expectedHeads {
						if strings.TrimSpace(blockHead) == "" {
							assert.Empty(t, actualHeads)
						} else {
							ref := txs[blockHead].Ref()
							assert.Containsf(t, actualHeads, ref, "failure on day %d blocknum %d", dayNum, blockNum)
							delete(actualHeads, ref)
						}
					}
					if len(actualHeads) > 0 {
						t.Fatalf("Test %s failed: on day %d there are unexpected heads in block %d: %v", tc.name, dayNum, blockNum, actualHeads)
					}
				}

				println(fmt.Sprintf("Blocks after %d day(s) pass:", dayNum+1))
				blocks.internalUpdate(time.Now().AddDate(0, 0, dayNum+1))
				println(blocks.String())
			}
		})
	}

	t.Run("end of DST (daylight saving time)", func(t *testing.T) {
		// DST ends at October 31th, 2021 at 03:00
		blocks := newDAGBlocks().(*trackingDAGBlocks)

		loc, _ := time.LoadLocation("Europe/Amsterdam")
		now := time.Date(2021, 10, 31, 1, 0, 0, 0, loc)
		blocks.internalUpdateTimestamps(now)

		// TX just before DST ends
		tx1 := testTX{sigt: time.Date(2021, 10, 31, 2, 0, 0, 0, loc), data: []byte{2}}
		blocks.internalAddTransaction(tx1)
		// TX just after DST ends
		tx2 := testTX{sigt: time.Date(2021, 10, 31, 3, 0, 1, 0, loc), data: []byte{3}, prev: []hash.SHA256Hash{tx1.Ref()}}
		blocks.internalAddTransaction(tx2)

		// Assert
		blocks.internalUpdate(now)
		actual := blocks.internalGet()
		assert.Empty(t, actual[0].heads)
		assert.Empty(t, actual[1].heads)
		assert.Len(t, actual[2].heads, 1)
		assert.Equal(t, tx2.Ref(), actual[2].heads[0])
	})
	t.Run("empty DAG", func(t *testing.T) {
		blocks := newDAGBlocks().(*trackingDAGBlocks)
		blocks.internalUpdate(time.Date(2021, 10, 10, 10, 11, 0, 0, time.FixedZone("Europe/Amsterdam", 5)))
		actual := blocks.internalGet()
		assert.Len(t, actual, numberOfBlocks)
		assert.Equal(t, "2021-10-10 00:00:00 +0000 UTC", getCurrentBlock(actual).start.String())
	})
}

func TestDAGBlock_XORHeads(t *testing.T) {
	t.Run("single head", func(t *testing.T) {
		expected := hash.SHA256Sum([]byte("Hello, World!"))
		blx := dagBlock{heads: []hash.SHA256Hash{expected}}
		assert.Equal(t, blx.xor(), expected)
	})
	t.Run("no heads", func(t *testing.T) {
		blx := dagBlock{heads: []hash.SHA256Hash{}}
		assert.Equal(t, blx.xor(), hash.EmptyHash())
	})
}

func TestMultiXOR(t *testing.T) {
	h1 := hash.SHA256Sum([]byte("Hello, World!"))
	h2 := hash.SHA256Sum([]byte("Hello, Universe!"))
	h3 := hash.SHA256Sum([]byte("Hello, Everything Else!"))
	expected, _ := hash.ParseHex("13735eb0bd447040661e1ca7f428e051ecaad15ea73e52e532423215f6836bb5")

	cases := [][]hash.SHA256Hash{
		{h1, h2, h3},
		{h1, h3, h2},
		{h3, h2, h1},
		{h3, h1, h2},
		{h2, h1, h3},
		{h2, h3, h1},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%v", c), func(t *testing.T) {
			actual := hash.EmptyHash()
			multiXOR(&actual, c...)
			assert.Equal(t, actual, expected)
		})
	}
}

type testTX struct {
	data []byte
	prev []hash.SHA256Hash
	sigt time.Time
}

func (t testTX) Ref() hash.SHA256Hash {
	return hash.SHA256Sum(t.data)
}

func (t testTX) Previous() []hash.SHA256Hash {
	return t.prev
}

func (t testTX) SigningTime() time.Time {
	return t.sigt
}

func (t testTX) Version() dag.Version {
	panic("implement me")
}

func (t testTX) TimelineID() hash.SHA256Hash {
	panic("implement me")
}

func (t testTX) TimelineVersion() int {
	panic("implement me")
}

func (t testTX) PayloadHash() hash.SHA256Hash {
	return hash.SHA256Sum(t.Ref().Slice())
}

func (t testTX) PayloadType() string {
	panic("implement me")
}

func (t testTX) SigningKey() jwk.Key {
	panic("implement me")
}

func (t testTX) SigningKeyID() string {
	panic("implement me")
}

func (t testTX) SigningAlgorithm() string {
	panic("implement me")
}

func (t testTX) MarshalJSON() ([]byte, error) {
	panic("implement me")
}

func (t testTX) Data() []byte {
	return t.data
}
