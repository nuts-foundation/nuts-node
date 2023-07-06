/*
 * Copyright (C) 2022 Nuts community
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

package events

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNATSConnectionPool_Acquire(t *testing.T) {
	t.Run("fails when context was cancelled", func(t *testing.T) {
		pool := NewNATSConnectionPool(Config{})
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

		pool := NewNATSConnectionPool(Config{})
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
		manager := createManager(t)

		pool := manager.Pool()

		err := manager.Start()
		assert.NoError(t, err)

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
