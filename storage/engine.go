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
	"errors"
	"fmt"
	"github.com/microsoft/go-mssqldb/azuread"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"github.com/nuts-foundation/nuts-node/storage/sql_migrations"
	"github.com/pressly/goose/v3"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

const storeShutdownTimeout = 5 * time.Second

// sqlSlowQueryThreshold specifies the threshold for logging slow SQL queries.
// If SQL queries take longer than this threshold, they will be logged as warnings.
const sqlSlowQueryThreshold = 200 * time.Millisecond

// New creates a new instance of the storage engine.
func New() Engine {
	return &engine{
		storesMux:          &sync.Mutex{},
		stores:             map[string]stoabs.Store{},
		sqlMigrationLogger: logrusInfoLogWriter{},
	}
}

type engine struct {
	datadir            string
	storesMux          *sync.Mutex
	stores             map[string]stoabs.Store
	databases          []database
	sessionDatabase    SessionDatabase
	sqlDB              *gorm.DB
	config             Config
	sqlMigrationLogger goose.Logger
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

	redisConfig := e.config.Session.Redis
	if redisConfig.isConfigured() {
		redisDB, err := createRedisDatabase(redisConfig)
		if err != nil {
			return fmt.Errorf("unable to configure Redis session database: %w", err)
		}
		client := redisDB.createClient()
		if err != nil {
			return fmt.Errorf("unable to configure redis client: %w", err)
		}
		e.sessionDatabase = NewRedisSessionDatabase(client, redisConfig.Database)
	} else {
		e.sessionDatabase = NewInMemorySessionDatabase()
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

	// Find right SQL adapter for ORM and migrations
	dbType := strings.Split(connectionString, ":")[0]
	if dbType == "sqlite" {
		connectionString = connectionString[strings.Index(connectionString, ":")+1:]
	} else if dbType == "mysql" {
		// MySQL DSN needs to be without mysql://
		// See https://github.com/go-sql-driver/mysql#examples
		connectionString = strings.TrimPrefix(connectionString, "mysql://")
	} else if dbType == "sqlserver" {
		// Use azuresql driver which wraps MS SQL Server driver, but adds Azure AD token provider.
		dbType = azuread.DriverName
	}
	db, err := goose.OpenDBWithDriver(dbType, connectionString)
	if err != nil {
		return err
	}
	var dialect goose.Dialect
	gormConfig := &gorm.Config{
		TranslateError: true,
		Logger: gormLogrusLogger{
			underlying:    log.Logger(),
			slowThreshold: sqlSlowQueryThreshold,
		},
	}
	// SQL migration files use env variables for substitutions.
	// TEXT SQL data type is really DB-specific, so we set a default here and override it for a specific database type (MS SQL).
	_ = os.Setenv("TEXT_TYPE", "TEXT")
	defer os.Unsetenv("TEXT_TYPE")
	switch dbType {
	case "sqlite":
		// SQLite does not support SELECT FOR UPDATE and allows only 1 active write transaction at any time,
		// and any other attempt to acquire a write transaction will directly return an error.
		// This is in contrast to most other SQL-databases, which let the 2nd thread wait for some time to acquire the lock.
		// The general advice for SQLite is to retry the operation, which is just poor-man's scheduling.
		// So to keep behavior consistent across databases, we'll just limit the number connections to 1 if it's a SQLite store.
		// With 1 connection, all actions will be performed sequentially. This impacts performance, but SQLite should not be used in production.
		// See https://github.com/nuts-foundation/nuts-node/pull/2589#discussion_r1399130608
		db.SetMaxOpenConns(1)
		dialector := sqlite.Dialector{Conn: db}
		e.sqlDB, err = gorm.Open(dialector, gormConfig)
		if err != nil {
			return err
		}
		dialect = goose.DialectSQLite3
	case "mysql":
		e.sqlDB, _ = gorm.Open(mysql.New(mysql.Config{
			Conn: db,
		}), gormConfig)
		dialect = goose.DialectMySQL
	case "postgres":
		e.sqlDB, _ = gorm.Open(postgres.New(postgres.Config{
			Conn: db,
		}), gormConfig)
		dialect = goose.DialectPostgres
	case azuread.DriverName:
		fallthrough
	case "sqlserver":
		_ = os.Setenv("TEXT_TYPE", "VARCHAR(MAX)")
		e.sqlDB, _ = gorm.Open(sqlserver.New(sqlserver.Config{
			Conn:       db,
			DriverName: azuread.DriverName,
		}), gormConfig)
		dialect = goose.DialectMSSQL
	default:
		return errors.New("unsupported SQL database")
	}
	goose.SetVerbose(log.Logger().Level >= logrus.DebugLevel)
	goose.SetLogger(e.sqlMigrationLogger)
	if err != nil {
		return err
	}
	gooseProvider, err := goose.NewProvider(dialect, db, sql_migrations.SQLMigrationsFS)
	if err != nil {
		return err
	}

	log.Logger().Debug("Running database migrations...")
	results, err := gooseProvider.Up(context.Background())
	for _, result := range results {
		log.Logger().Debug(result.String())
	}
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}
	log.Logger().Infof("Completed %d migrations", len(results))

	return nil
}

func sqliteConnectionString(datadir string) string {
	return "sqlite:file:" + path.Join(datadir, "sqlite.db?_pragma=foreign_keys(1)&journal_mode(WAL)")
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

type logrusInfoLogWriter struct {
}

func (m logrusInfoLogWriter) Printf(format string, v ...interface{}) {
	log.Logger().Info(fmt.Sprintf(format, v...))
}

func (m logrusInfoLogWriter) Fatalf(format string, v ...interface{}) {
	log.Logger().Errorf(format, v...)
}
