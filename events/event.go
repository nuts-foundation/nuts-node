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
	"path"
	"time"

	natsServer "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/nuts-node/core"
)

const moduleName = "Events"

type manager struct {
	config  Config
	pool    ConnectionPool
	server  *natsServer.Server
	streams map[string]Stream
}

// NewManager returns a new event manager
func NewManager() Event {
	config := DefaultConfig()

	return &manager{
		config:  config,
		streams: map[string]Stream{},
	}
}

func (m *manager) Name() string {
	return moduleName
}

func (m *manager) Config() interface{} {
	return &m.config
}

func (m *manager) Pool() ConnectionPool {
	return m.pool
}

// Configure the storageDir and setup the predefined set of streams.
// Nats is very picky about the stream and consumer setup, therefore we predefine them all in this engine.
func (m *manager) Configure(config core.ServerConfig) error {
	if m.config.Nats.StorageDir == "" {
		m.config.Nats.StorageDir = path.Join(config.Datadir, "events")
	}

	m.pool = NewNATSConnectionPool(m.config)

	// register Transaction stream
	m.streams[TransactionsStream] = newStream(&nats.StreamConfig{
		Name:      TransactionsStream,
		Subjects:  []string{"TRANSACTIONS.*"},
		Retention: nats.LimitsPolicy,
		MaxAge:    168 * time.Hour, // week
		Discard:   nats.DiscardOld,
		Storage:   nats.FileStorage,
	}, true)

	// register Data stream
	m.streams[DataStream] = newStream(&nats.StreamConfig{
		Name:      DataStream,
		Subjects:  []string{"DATA.*"},
		Retention: nats.LimitsPolicy,
		MaxAge:    168 * time.Hour, // week
		Discard:   nats.DiscardOld,
		Storage:   nats.FileStorage,
	}, true)

	return nil
}

func (m *manager) GetStream(streamName string) Stream {
	s := m.streams[streamName]
	return s
}

func (m *manager) Start() error {
	server, err := natsServer.NewServer(&natsServer.Options{
		JetStream: true,
		Port:      m.config.Nats.Port,
		Host:      m.config.Nats.Hostname,
		StoreDir:  m.config.Nats.StorageDir,
		NoSigs:    true, // Signals are handled by Nuts node, Nats Server is shut down when Event Engine is shut down.
	})
	if err != nil {
		return err
	}

	m.server = server
	server.Start()

	return nil
}

func (m *manager) Shutdown() error {
	if m.server == nil {
		return nil
	}

	m.server.Shutdown()
	m.pool.Shutdown()
	m.server.WaitForShutdown()

	return nil
}
