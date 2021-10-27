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

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/events/log"

	natsServer "github.com/nats-io/nats-server/v2/server"
)

const moduleName = "Event manager"

type manager struct {
	config *Config
	server *natsServer.Server
}

// NewManager returns a new event manager
func NewManager() Event {
	return &manager{config: &Config{}}
}

func (m *manager) Name() string {
	return moduleName
}

func (m *manager) Config() interface{} {
	return &m.config
}

func (m *manager) Configure(config core.ServerConfig) error {
	if m.config.StorageDir == "" {
		m.config.StorageDir = path.Join(config.Datadir, "events")
	}

	return nil
}

func (m *manager) Start() error {
	log.Logger().Debugf("starting %s", moduleName)

	server, err := natsServer.NewServer(&natsServer.Options{
		JetStream: true,
		Port:      m.config.Port,
		Host:      m.config.Hostname,
		StoreDir:  m.config.StorageDir,
	})
	if err != nil {
		return err
	}

	m.server = server

	server.Start()

	log.Logger().Infof("started %s", moduleName)

	return nil
}

func (m *manager) Shutdown() error {
	if m.server == nil {
		return nil
	}

	log.Logger().Debugf("shutting down %s", moduleName)

	m.server.Shutdown()
	m.server.WaitForShutdown()

	log.Logger().Infof("%s shutdown complete", moduleName)

	return nil
}
