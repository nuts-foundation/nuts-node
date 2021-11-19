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

package p2p

import (
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"sync"
)

type stubMessenger struct {
	out []*protobuf.NetworkMessage
	sync.Mutex
	recvWaitGroup sync.WaitGroup
}

func (s *stubMessenger) MessagesSent() int {
	s.Lock()
	defer s.Unlock()
	return len(s.out)
}

func (s *stubMessenger) Send(message *protobuf.NetworkMessage) error {
	s.Lock()
	defer s.Unlock()
	s.out = append(s.out, message)
	return nil
}

func (s *stubMessenger) Recv() (*protobuf.NetworkMessage, error) {
	s.recvWaitGroup.Add(1)
	s.recvWaitGroup.Wait()
	return nil, nil
}
