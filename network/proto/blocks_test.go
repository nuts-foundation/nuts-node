package proto

import (
	"encoding/hex"
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

func tc(transactions []tx, heads ...string) testCase {
	return testCase{
		txs:   transactions,
		heads: heads,
	}
}

// Test cases visualized with https://asciiflow.com/

/*
     │        │
┌───┐ │  ┌───┐ │  ┌───┐
│ A ├─┼─►│ B ├─┼─►│ C │
└───┘ │  └───┘ │  └───┘
     │        │
*/
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
	numberOfBlocks := 3
	for _, tc := range testCases() {
		t.Run(tc.name, func(t *testing.T) {
			blocks := NewDAGBlocks(numberOfBlocks)
			txs := make(map[string]dag.Transaction, 0)
			latestTXAge := 0
			for _, currTX := range tc.txs {
				// Derive ref from name
				ref := hash.SHA256Hash{}
				nameAsHex := currTX.name
				if len(nameAsHex) % 2 == 1 {
					nameAsHex = "0" + nameAsHex
				}
				bts, err := hex.DecodeString(nameAsHex)
				if !assert.NoError(t, err) {
					return
				}
				for i, b := range bts {
					ref[i] = b
				}
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
					ref:  ref,
					prev: prevs,
					sigt: time.Now().AddDate(0, 0, currTX.time - numberOfBlocks + 1),
				}
				if currTX.time > latestTXAge {
					latestTXAge = currTX.time
				}
				txs[currTX.name] = tx
				err = blocks.AddTransaction(&tx, nil)
				if !assert.NoError(t, err) {
					return
				}
				//println(blocks.String())
			}
			println(blocks.String())
			for dayNum := 0; dayNum < latestTXAge + 1; dayNum++ {
				// Assert blocks
				expectedBlockHeads := strings.Split(tc.heads[dayNum], ", ")
				for blockNum, blockHeadsConcatted := range expectedBlockHeads {
					blockHeads := strings.Split(strings.TrimSpace(blockHeadsConcatted), " ")
					for _, blockHead := range blockHeads {
						heads := blocks.heads()
						if strings.TrimSpace(blockHead) == "" {
							assert.Empty(t, heads[blockNum])
						} else {
							ref := txs[blockHead].Ref()
							assert.Contains(t, heads[blockNum], ref)
						}
					}
				}

				println(fmt.Sprintf("Blocks after %d day(s) pass:", dayNum+ 1))
				blocks.update(time.Now().AddDate(0, 0, dayNum+ 1))
				println(blocks.String())
			}
		})
	}
}

type testTX struct {
	ref hash.SHA256Hash
	prev []hash.SHA256Hash
	sigt time.Time
}

func (t testTX) Ref() hash.SHA256Hash {
	return t.ref
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
	panic("implement me")
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
	panic("implement me")
}
