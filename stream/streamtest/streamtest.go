// Package streamtest provides utilities for event-stream testing.
package streamtest

import (
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/nuts-foundation/nuts-node/stream"
)

var streamN atomic.Uint64

// Pipe returns both ends of an event-stream ready for use.
// No need to Close.
func Pipe(t *testing.T) (stream.Appender, stream.Iterator) {
	file := filepath.Join(t.TempDir(), strconv.FormatUint(streamN.Add(1), 16)+"_stream")
	w := stream.OpenAppender(file)
	r := stream.OpenIterator(file)
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Error("event-stream appender Close error:", err)
		}
		if err := r.Close(); err != nil {
			t.Error("event-stream iterator Close error:", err)
		}
	})
	return w, r
}
