/*
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

package grpc

import (
	"encoding/json"
	"errors"
	"github.com/magiconair/properties/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func Test_ReceiveMessages(t *testing.T) {
	t.Run("receive message", func(t *testing.T) {
		received := 0

		streamer := stubStreamReceiver{}
		streamer.expectedMessage = "foobar"
		err := ReceiveMessages(&streamer, func() interface{} {
			var receivedMessage string
			return &receivedMessage
		}, func(msg interface{}) {
			received++
			assert.Equal(t, *(msg.(*string)), "foobar")
		})
		assert.Equal(t, err, &closedErr{})
		assert.Equal(t, received, 1)
	})
	t.Run("error", func(t *testing.T) {
		received := 0

		streamer := stubStreamReceiver{}
		expectedError := errors.New("some failure")
		streamer.expectedError = expectedError
		err := ReceiveMessages(&streamer, func() interface{} {
			var receivedMessage string
			return &receivedMessage
		}, func(msg interface{}) {
			received++
		})
		assert.Equal(t, err, expectedError)
		assert.Equal(t, received, 0)
	})

}

type stubStreamReceiver struct {
	expectedError   error
	expectedMessage interface{}
}

func (s *stubStreamReceiver) RecvMsg(m interface{}) error {
	if s.expectedMessage != nil {
		b, err := json.Marshal(s.expectedMessage)
		if err != nil {
			return err
		}
		err = json.Unmarshal(b, m)
		if err != nil {
			return err
		}
		s.expectedMessage = nil
		return nil
	}
	if s.expectedError != nil {
		return s.expectedError
	}
	return &closedErr{}
}

type closedErr struct{}

func (g closedErr) Error() string {
	return ""
}

func (g closedErr) GRPCStatus() *status.Status {
	return status.New(codes.Canceled, "connection closed")
}
