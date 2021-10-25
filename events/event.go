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
	"path"
	"strconv"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/events/log"

	natsServer "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const moduleName = "Event manager"

var (
	retryDurations = []time.Duration{
		30 * time.Second,
		15 * time.Minute,
		time.Hour,
		6 * time.Hour,
		24 * time.Hour,
	}
)

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
	return m.config
}

func (m *manager) Configure(config core.ServerConfig) error {
	if m.config.StorageDir == "" {
		m.config.StorageDir = path.Join(config.Datadir, "events")
	}

	return nil
}

func (m *manager) getClient() (Conn, error) {
	if !m.server.ReadyForConnections(0) {
		return nil, errors.New("server is not ready for connection")
	}

	conn, err := nats.Connect(m.server.ClientURL())
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (m *manager) startRetryHandler() {
	var (
		conn    Conn
		msgChan chan *nats.Msg
	)

	// Wait until a connection has established
	for {
		var err error

		conn, err = m.getClient()
		if err == nil {
			msgChan, err = RetryStream.Subscribe(conn, "*")
			if err == nil {
				break
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Process retries
	for msg := range msgChan {
		retries, _ := strconv.Atoi(msg.Header.Get("retries"))
		subject := msg.Header.Get("subject")

		var retryDuration time.Duration

		if retries > len(retryDurations)-1 {
			retryDuration = retryDurations[len(retryDurations)-1]
		} else {
			retryDuration = retryDurations[retries]
		}

		newMsg := nats.NewMsg(subject)
		newMsg.Header.Set("retries", strconv.Itoa(retries+1))

		if err := PrivateCredentialStream.Publish(conn, newMsg, nats.AckWait(retryDuration)); err != nil {
			if err := msg.Ack(); err != nil {
				log.Logger().Errorf("failed to ack message in retry stream: %#v", err)
			}
		}
	}
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

	go m.startRetryHandler()

	server.Start()

	log.Logger().Infof("started %s", moduleName)

	return nil
}

func (m *manager) Shutdown() error {
	if m.server == nil {
		return nil
	}

	log.Logger().Debugf("shutting down %s", moduleName)

	// give shutdown command
	m.server.Shutdown()

	// wait for shutdown to complete
	m.server.WaitForShutdown()
	log.Logger().Infof("%s shutdown complete", moduleName)

	return nil
}
