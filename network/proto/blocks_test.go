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
	name  string
	txs   []tx
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
			│ A ├─┼─►│ B ├─┼─►│ C ├─►│ D │ (D in future)
			└───┘ │  └───┘ │  └───┘  └───┘
			      │        │
		*/
		{
			name: "simple + D in future",
			txs: []tx{
				tx{"A", 0, noPrevs()},
				tx{"B", 1, prev("A")},
				tx{"C", 2, prev("B")},
				tx{"D", 5, prev("C")},
			},
			heads: []string{
				"A, B, D",
				"B, C, D",
				"C,  , D",
				"C,  , D",
				"C, D",
				"D",
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
			blocks := NewDAGBlocks().(*trackingDAGBlocks)
			txs := make(map[string]dag.Transaction, 0)
			latestTXAge := 0
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
				if currTX.time > latestTXAge {
					latestTXAge = currTX.time
				}
				txs[currTX.name] = tx
				err := blocks.AddTransaction(&tx, nil)
				if !assert.NoError(t, err) {
					return
				}
			}
			println(blocks.String())
			for dayNum := 0; dayNum < latestTXAge+1; dayNum++ {
				// Assert blocks
				expectedBlockHeads := strings.Split(tc.heads[dayNum], ", ")
				for blockNum, blockHeadsConcatted := range expectedBlockHeads {
					blockHeads := strings.Split(strings.TrimSpace(blockHeadsConcatted), " ")
					for _, blockHead := range blockHeads {
						heads := blocks.heads()
						if strings.TrimSpace(blockHead) == "" {
							assert.Empty(t, heads[blockNum].Heads)
						} else {
							ref := txs[blockHead].Ref()
							assert.Contains(t, heads[blockNum].Heads, ref)
						}
					}
				}

				println(fmt.Sprintf("Blocks after %d day(s) pass:", dayNum+1))
				blocks.update(time.Now().AddDate(0, 0, dayNum+1))
				println(blocks.String())
			}
		})
	}
}

func TestDAGBlock_XORHeads(t *testing.T) {
	t.Run("single head", func(t *testing.T) {
		expected := hash.SHA256Sum([]byte("Hello, World!"))
		blx := DAGBlock{Heads: []hash.SHA256Hash{expected}}
		assert.Equal(t, blx.XOR(), expected)
	})
	t.Run("no heads", func(t *testing.T) {
		blx := DAGBlock{Heads: []hash.SHA256Hash{}}
		assert.Equal(t, blx.XOR(), hash.EmptyHash())
	})
}

func TestMultiXOR(t *testing.T) {
	h1 := hash.SHA256Sum([]byte("Hello, World!"))
	h2 := hash.SHA256Sum([]byte("Hello, Universe!"))
	h3 := hash.SHA256Sum([]byte("Hello, Everything Else!"))
	expected, _ := hash.ParseHex("13735eb0bd447040661e1ca7f428e051ecaad15ea73e52e532423215f6836bb5")
	actual := hash.EmptyHash()
	multiXOR(&actual, h1, h2, h3)
	assert.Equal(t, actual, expected)
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
