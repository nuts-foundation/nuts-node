package main

import (
	"flag"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"log"
	"math"
	"os"
	"runtime/pprof"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func main() {
	// prep profiler
	flag.Parse()
	var f *os.File
	var err error
	if *cpuprofile != "" {
		f, err = os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
	}

	// build tree
	leafSize := uint32(512)
	maxDepth := 16
	proto := tree.NewIblt()
	dataTree := tree.NewBottomUp(proto, leafSize)
	numLeaves := uint32(math.Pow(2, float64(maxDepth)))
	dirties := map[uint32][]byte{}
	for i := uint32(0); i < numLeaves; i++ {
		dataTree.Insert(hash.RandomHash(), i*leafSize)
	}
	dirties, _ = dataTree.GetUpdates()
	profileTree := tree.NewBottomUp(proto, leafSize)

	// start profiler after tree construction
	if *cpuprofile != "" {
		err = pprof.StartCPUProfile(f)
		if err != nil {
			log.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	// profile this:
	_ = profileTree.Load(dirties)
}
