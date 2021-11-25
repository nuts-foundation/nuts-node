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

// ReceiveMessages is a helper function which receives messages from the given StreamReceiver.
// The supplied callbacks are invoked when a message is received or an error occurs. The function blocks until an error occurs.
func ReceiveMessages(receiver StreamReceiver, messageCreator func() interface{}, onMessage func(msg interface{})) error {
	for {
		msg := messageCreator()
		err := receiver.RecvMsg(msg)
		if err != nil {
			return err
		}
		onMessage(msg)
	}
}

// StreamReceiver defines a function for receiving a message through a gRPC stream. It is implemented by both grpc.ServerStream and grpc.ClientStream.
type StreamReceiver interface {
	RecvMsg(m interface{}) error
}
