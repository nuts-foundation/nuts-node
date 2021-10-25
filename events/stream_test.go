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
	"github.com/golang/mock/gomock"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

func TestStream_Middleware(t *testing.T) {
	msg := nats.NewMsg("original-subject")

	err := RetryStream.middleware(msg)
	assert.NoError(t, err)

	assert.Equal(t, "nuts.retry", msg.Subject)
	assert.Equal(t, "original-subject", msg.Header.Get("subject"))
	assert.Equal(t, "0", msg.Header.Get("retries"))
}

func TestStream_Publish(t *testing.T) {
	jsMock := NewMockJetStreamContext(gomock.NewController(t))
	jsMock.EXPECT().StreamInfo(DisposableStream.Config().Name).Return(nil, nil)
	jsMock.EXPECT().PublishMsg(nats.NewMsg("test"))

	conn := NewMockConn(gomock.NewController(t))
	conn.EXPECT().JetStream().Return(jsMock, nil)
	conn.EXPECT().JetStream().Return(jsMock, nil)

	err := DisposableStream.Publish(conn, nats.NewMsg("test"))
	assert.NoError(t, err)
}
