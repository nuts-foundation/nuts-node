package events

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nats-io/nats.go"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNATSConnectionPool_Acquire(t *testing.T) {
	t.Run("fails when context was cancelled", func(t *testing.T) {
		pool := NewNATSConnectionPool(&Config{})
		pool.connectFunc = func(url string, options ...nats.Option) (Conn, error) {
			return nil, errors.New("random error")
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, js, err := pool.Acquire(ctx)

		assert.Equal(t, context.Canceled, err)
		assert.Nil(t, conn)
		assert.Nil(t, js)
	})

	t.Run("connection should be retried", func(t *testing.T) {
		called := false

		ctrl := gomock.NewController(t)

		mockJs := NewMockJetStreamContext(ctrl)
		mockConn := NewMockConn(ctrl)
		mockConn.EXPECT().JetStream().Return(mockJs, nil)

		pool := NewNATSConnectionPool(&Config{})
		pool.connectFunc = func(url string, options ...nats.Option) (Conn, error) {
			if called {
				return mockConn, nil
			}

			called = true

			return nil, errors.New("random error")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		conn, js, err := pool.Acquire(ctx)

		assert.NoError(t, err)
		assert.NotNil(t, conn)
		assert.NotNil(t, js)
	})

	t.Run("ok - NATS integration test", func(t *testing.T) {
		manager := NewManager().(*manager)
		manager.config.Port = 402249

		pool := manager.Pool()

		err := manager.Start()
		assert.NoError(t, err)

		defer manager.Shutdown()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		wc := sync.WaitGroup{}
		wc.Add(50)

		for i := 0; i < 50; i++ {
			go func() {
				conn, js, err := pool.Acquire(ctx)

				assert.NoError(t, err)
				assert.NotNil(t, js)
				assert.NotNil(t, conn)

				wc.Done()
			}()
		}

		wc.Wait()
	})
}
