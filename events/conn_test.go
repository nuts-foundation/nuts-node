package events

import (
	"context"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

func TestNATSConnectionPool_Acquire(t *testing.T) {
	manager := NewManager().(*manager)

	pool := manager.Pool()

	err := manager.Start()
	assert.NoError(t, err)

	defer manager.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wc := sync.WaitGroup{}
	wc.Add(500)

	for i := 0; i < 500; i++ {
		go func() {
			conn, js, err := pool.Acquire(ctx)

			assert.NoError(t, err)
			assert.NotNil(t, js)
			assert.NotNil(t, conn)

			wc.Done()
		}()
	}

	wc.Wait()
}
