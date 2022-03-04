package v2

import (
	"github.com/nuts-foundation/nuts-node/network/transport/v2/tree"
	"sync"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

const treeLeafSize = 512

type StateDAG interface {
	AddNewTx(ref hash.SHA256Hash, clock uint32) error
	GetLC() uint32
	GetXor() (hash.SHA256Hash, uint32)
	GetXorAt(clock uint32) (hash.SHA256Hash, uint32)
}

type stateDAG struct {
	seenTx     map[hash.SHA256Hash]bool
	maxKnownLC uint32
	xorTree    tree.Tree
	mutex      sync.RWMutex
}

func newStateDAG() StateDAG {
	return &stateDAG{
		xorTree: tree.New(tree.NewXor(), treeLeafSize),
		seenTx:  make(map[hash.SHA256Hash]bool),
		mutex:   sync.RWMutex{},
	}
}

func (st *stateDAG) AddNewTx(ref hash.SHA256Hash, clock uint32) error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	if _, ok := st.seenTx[ref]; !ok {
		// add to seenTx
		st.seenTx[ref] = true
		// update LC
		if clock > st.maxKnownLC {
			st.maxKnownLC = clock
		}
		// add to xorTree
		err := st.xorTree.Insert(ref, clock)
		if err != nil {
			return err
		}
	}

	return nil
}

func (st *stateDAG) GetLC() uint32 {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	return st.maxKnownLC
}

func (st *stateDAG) GetXor() (hash.SHA256Hash, uint32) {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	data := st.xorTree.GetRoot()
	return data.(*tree.Xor).Hash, st.maxKnownLC
}

func (st *stateDAG) GetXorAt(clock uint32) (hash.SHA256Hash, uint32) {
	st.mutex.RLock()
	defer st.mutex.RUnlock()

	data, trueClock := st.xorTree.GetZeroTo(clock)
	return data.(*tree.Xor).Hash, trueClock
}
