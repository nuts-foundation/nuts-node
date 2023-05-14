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

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"github.com/redis/go-redis/v9"
	"strings"
	"sync"
	"time"
)

const storeShutdownTimeout = 5 * time.Second

// New creates a new instance of the storage engine.
func New() Engine {
	return &engine{
		storesMux: &sync.Mutex{},
		stores:    map[string]stoabs.Store{},
	}
}

type engine struct {
	datadir   string
	storesMux *sync.Mutex
	stores    map[string]stoabs.Store
	databases []database
	config    Config
}

func (e *engine) Config() interface{} {
	return &e.config
}

// Name returns the name of the engine.
func (e engine) Name() string {
	return "Storage"
}

func (e engine) Start() error {
	return nil
}

func (e engine) Shutdown() error {
	e.storesMux.Lock()
	defer e.storesMux.Unlock()

	shutdown := func(store stoabs.Store) error {
		// Refactored to separate function, otherwise defer would be in for loop which leaks resources.
		ctx, cancel := context.WithTimeout(context.Background(), storeShutdownTimeout)
		defer cancel()
		return store.Close(ctx)
	}

	failures := false
	for storeName, store := range e.stores {
		err := shutdown(store)
		if err != nil {
			log.Logger().
				WithError(err).
				WithField(core.LogFieldStore, storeName).
				Error("Failed to close store")
			failures = true
		}
	}
	if failures {
		return errors.New("one or more stores failed to close")
	}
	return nil
}

func (e *engine) Configure(config core.ServerConfig) error {
	e.datadir = config.Datadir
	if e.config.SQL.isConfigured() {
		log.Logger().Info("SQL database support enabled.")
		log.Logger().Warn("SQL database support is still experimental: do not use for production environments!")
		sqlDB, err := createSQLDatabase(e.config.SQL)
		if err != nil {
			return fmt.Errorf("unable to configure SQL database: %w", err)
		}
		e.databases = append(e.databases, sqlDB)
	}
	if e.config.Redis.isConfigured() {
		redisDB, err := createRedisDatabase(e.config.Redis)
		if err != nil {
			return fmt.Errorf("unable to configure Redis database: %w", err)
		}
		e.databases = append(e.databases, redisDB)
		log.Logger().Info("Redis database support enabled.")
		log.Logger().Warn("Redis database support is still experimental: do not use for production environments!")
		redis.SetLogger(redisLogWriter{logger: log.Logger()})
	}
	bboltDB, err := createBBoltDatabase(config.Datadir, e.config.BBolt)
	if err != nil {
		return fmt.Errorf("unable to configure BBolt database: %w", err)
	}
	e.databases = append(e.databases, bboltDB)
	return nil
}

func (e *engine) GetProvider(moduleName string) Provider {
	return &provider{
		moduleName: strings.ToLower(moduleName),
		engine:     e,
	}
}

type provider struct {
	moduleName string
	engine     *engine
}

func (p *provider) GetSQLStore() *sql.DB {
	for _, curr := range p.engine.databases {
		if sqlDB, ok := curr.(*sqlDatabase); ok {
			return sqlDB.db
		}
	}
	return nil
}

func (p *provider) GetKVStore(name string, class Class) (stoabs.KVStore, error) {
	p.engine.storesMux.Lock()
	defer p.engine.storesMux.Unlock()

	// TODO: For now, we ignore class since we only support BBolt.
	// When other database types with other storage classes are supported (e.g. Redis) we'll be matching them here,
	// to find the right one:
	// 1. Check manual binding of specific store to a configured database (e.g. `network/connections -> redis0`)
	// 2. Otherwise: find database whose storage class matches the requested class
	// 3. Otherwise (if no storage class matches, e.g. no `persistent` database configured): use "lower" storage class, but only in non-strict mode.
	var db database
	for _, curr := range p.engine.databases {
		if curr.getClass() == class {
			db = curr
			break
		}
	}

	if db == nil {
		db = p.engine.databases[0]
	}

	// TODO: If the requested class isn't available and we're in strict mode, return an error

	store, err := p.getStore(p.moduleName, name, db)
	if store == nil {
		return nil, err
	}
	return store.(stoabs.KVStore), err
}

func (p *provider) getStore(moduleName string, name string, adapter database) (stoabs.Store, error) {
	if len(moduleName) == 0 {
		return nil, errors.New("invalid store moduleName")
	}
	if len(name) == 0 {
		return nil, errors.New("invalid store name")
	}
	key := moduleName + "/" + name
	store := p.engine.stores[key]
	if store != nil {
		return store, nil
	}
	store, err := adapter.createStore(moduleName, name)
	if err == nil {
		p.engine.stores[key] = store
	}
	return store, err
}
