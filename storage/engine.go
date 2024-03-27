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
	"embed"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/amacneil/dbmate/v2/pkg/dbmate"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/mysql"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/postgres"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/sqlite"
)

const storeShutdownTimeout = 5 * time.Second

// sqlSlowQueryThreshold specifies the threshold for logging slow SQL queries.
// If SQL queries take longer than this threshold, they will be logged as warnings.
const sqlSlowQueryThreshold = 200 * time.Millisecond

//go:embed sql_migrations/*.sql
var sqlMigrationsFS embed.FS

// New creates a new instance of the storage engine.
func New() Engine {
	return &engine{
		storesMux:       &sync.Mutex{},
		stores:          map[string]stoabs.Store{},
		sessionDatabase: NewInMemorySessionDatabase(),
	}
}

type engine struct {
	datadir         string
	storesMux       *sync.Mutex
	stores          map[string]stoabs.Store
	databases       []database
	sessionDatabase SessionDatabase
	sqlDB           *gorm.DB
	config          Config
}

func (e *engine) Config() interface{} {
	return &e.config
}

// Name returns the name of the engine.
func (e *engine) Name() string {
	return "Storage"
}

func (e *engine) Start() error {
	return nil
}

func (e *engine) Shutdown() error {
	e.storesMux.Lock()
	defer e.storesMux.Unlock()

	// Close KV stores
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

	// Close session database
	e.sessionDatabase.close()
	// Close SQL db
	if e.sqlDB != nil {
		underlyingDB, err := e.sqlDB.DB()
		if err != nil {
			return err
		}
		return underlyingDB.Close()
	}
	return nil
}

func (e *engine) Configure(config core.ServerConfig) error {
	e.datadir = config.Datadir

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

	if err := e.initSQLDatabase(); err != nil {
		return fmt.Errorf("failed to initialize SQL database: %w", err)
	}

	return nil
}

func (e *engine) GetProvider(moduleName string) Provider {
	return &provider{
		moduleName: strings.ToLower(moduleName),
		engine:     e,
	}
}

func (e *engine) GetSessionDatabase() SessionDatabase {
	return e.sessionDatabase
}

func (e *engine) GetSQLDatabase() *gorm.DB {
	return e.sqlDB
}

// initSQLDatabase initializes the SQL database connection.
// If the connection string is not configured, it defaults to a SQLite database, stored in the node's data directory.
func (e *engine) initSQLDatabase() error {
	connectionString := e.config.SQL.ConnectionString
	if len(connectionString) == 0 {
		connectionString = sqliteConnectionString(e.datadir)
	}

	// Find right SQL adapter
	type sqlAdapter struct {
		connector func(sqlDB *sql.DB) gorm.Dialector
	}
	adapters := map[string]sqlAdapter{
		"sqlite": {
			connector: func(sqlDB *sql.DB) gorm.Dialector {
				return &sqlite.Dialector{Conn: sqlDB}
			},
		},
		"postgres": {
			connector: func(sqlDB *sql.DB) gorm.Dialector {
				return postgres.New(postgres.Config{Conn: sqlDB})
			},
		},
		"mysql": {
			connector: func(sqlDB *sql.DB) gorm.Dialector {
				return mysql.New(mysql.Config{Conn: sqlDB})
			},
		},
	}
	var adapter *sqlAdapter
	for prefix, curr := range adapters {
		if strings.HasPrefix(connectionString, prefix+":") {
			adapter = &curr
			break
		}
	}
	if adapter == nil {
		return errors.New("unsupported SQL database")
	}

	// Open connection and migrate
	var err error
	connectionURL, err := url.Parse(connectionString)
	if err != nil {
		return err
	}
	dbMigrator := dbmate.New(connectionURL)
	migratorDriver, err := dbMigrator.Driver()
	if err != nil {
		return err
	}
	sqlDB, err := migratorDriver.Open()
	if err != nil {
		return err
	}
	if strings.HasPrefix(connectionString, "sqlite:") {
		// SQLite does not support SELECT FOR UPDATE and allows only 1 active write transaction at any time,
		// and any other attempt to acquire a write transaction will directly return an error.
		// This is in contrast to most other SQL-databases, which let the 2nd thread wait for some time to acquire the lock.
		// The general advice for SQLite is to retry the operation, which is just poor-man's scheduling.
		// So to keep behavior consistent across databases, we'll just limit the number connections to 1 if it's a SQLite store.
		// With 1 connection, all actions will be performed sequentially. This impacts performance, but SQLite should not be used in production.
		// See https://github.com/nuts-foundation/nuts-node/pull/2589#discussion_r1399130608
		sqlDB.SetMaxOpenConns(1)
	}
	log.Logger().Debug("Running database migrations...")

	// we need the connectionString with adapter specific prefix here
	dbMigrator.FS = sqlMigrationsFS
	dbMigrator.MigrationsDir = []string{"sql_migrations"}
	dbMigrator.AutoDumpSchema = false
	dbMigrator.Log = sqlMigrationLogger{}
	if err = dbMigrator.CreateAndMigrate(); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	e.sqlDB, err = gorm.Open(adapter.connector(sqlDB), &gorm.Config{
		TranslateError: true,
		Logger: gormLogrusLogger{
			underlying:    log.Logger(),
			slowThreshold: sqlSlowQueryThreshold,
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func sqliteConnectionString(datadir string) string {
	return "sqlite:file:" + path.Join(datadir, "sqlite.db?_journal_mode=WAL&_foreign_keys=on")
}

type provider struct {
	moduleName string
	engine     *engine
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

type sqlMigrationLogger struct {
}

func (m sqlMigrationLogger) Write(p []byte) (n int, err error) {
	log.Logger().Info(string(p))
	return len(p), nil
}
