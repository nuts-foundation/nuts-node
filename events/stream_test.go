/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestStream_Subscribe(t *testing.T) {
	t.Run("subscribe works and stream is created only once", func(t *testing.T) {

		disposableStream := NewDisposableStream("example", []string{}, 100)

		mockStreamInfo := &nats.StreamInfo{}
		ctrl := gomock.NewController(t)

		jsFirst := NewMockJetStreamContext(ctrl)
		jsFirst.EXPECT().StreamInfo("example").Return(nil, nats.ErrStreamNotFound)
		jsFirst.EXPECT().AddStream(disposableStream.Config()).Return(mockStreamInfo, nil)
		jsFirst.EXPECT().Subscribe("subject", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&nats.Subscription{}, nil)

		jsLast := NewMockJetStreamContext(ctrl)
		jsLast.EXPECT().Subscribe("subject", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&nats.Subscription{}, nil)

		conn := NewMockConn(ctrl)
		conn.EXPECT().JetStream().Return(jsFirst, nil)
		conn.EXPECT().JetStream().Return(jsLast, nil)

		err := disposableStream.Subscribe(conn, "test", "subject", nil)
		assert.NoError(t, err)

		// The second time it should only subscribe, not re-create the stream
		err = disposableStream.Subscribe(conn, "test", "subject", nil)
		assert.NoError(t, err)
	})

	t.Run("stream is not created when it exists", func(t *testing.T) {
		disposableStream := NewDisposableStream("example", []string{}, 100)

		mockStreamInfo := &nats.StreamInfo{}
		ctrl := gomock.NewController(t)

		js := NewMockJetStreamContext(ctrl)
		js.EXPECT().StreamInfo("example").Return(mockStreamInfo, nil)
		js.EXPECT().Subscribe("subject", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&nats.Subscription{}, nil)

		conn := NewMockConn(ctrl)
		conn.EXPECT().JetStream().Return(js, nil)

		err := disposableStream.Subscribe(conn, "test", "subject", nil)
		assert.NoError(t, err)
	})

	t.Run("error is returned when add-stream fails", func(t *testing.T) {
		disposableStream := NewDisposableStream("example", []string{}, 100)

		ctrl := gomock.NewController(t)

		js := NewMockJetStreamContext(ctrl)
		js.EXPECT().StreamInfo("example").Return(nil, nats.ErrStreamNotFound)
		js.EXPECT().AddStream(disposableStream.Config()).Return(nil, errors.New("random error"))

		conn := NewMockConn(ctrl)
		conn.EXPECT().JetStream().Return(js, nil)

		err := disposableStream.Subscribe(conn, "test", "subject", nil)
		assert.Error(t, err)
	})

	t.Run("error is returned when chan-subscribe fails", func(t *testing.T) {
		disposableStream := NewDisposableStream("example", []string{}, 100)

		mockStreamInfo := &nats.StreamInfo{}
		ctrl := gomock.NewController(t)

		js := NewMockJetStreamContext(ctrl)
		js.EXPECT().StreamInfo("example").Return(mockStreamInfo, nil)
		js.EXPECT().Subscribe("subject", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("random error"))

		conn := NewMockConn(ctrl)
		conn.EXPECT().JetStream().Return(js, nil)

		err := disposableStream.Subscribe(conn, "test", "subject", nil)
		assert.Error(t, err)
	})

	t.Run("error is returned when stream-info fails", func(t *testing.T) {
		disposableStream := NewDisposableStream("example", []string{}, 100)

		ctrl := gomock.NewController(t)

		js := NewMockJetStreamContext(ctrl)
		js.EXPECT().StreamInfo("example").Return(nil, errors.New("random error"))

		conn := NewMockConn(ctrl)
		conn.EXPECT().JetStream().Return(js, nil)

		err := disposableStream.Subscribe(conn, "test", "subject", nil)
		assert.Error(t, err)
	})

	t.Run("error is returned when jetstream fails", func(t *testing.T) {
		disposableStream := NewDisposableStream("example", []string{}, 100)

		ctrl := gomock.NewController(t)

		conn := NewMockConn(ctrl)
		conn.EXPECT().JetStream().Return(nil, errors.New("random error"))

		err := disposableStream.Subscribe(conn, "test", "subject", nil)
		assert.Error(t, err)
	})
}

func TestStream_ClientOpts(t *testing.T) {
	disposableStream := NewDisposableStream("example", []string{}, 100)

	assert.Len(t, disposableStream.ClientOpts(), 3)
}
