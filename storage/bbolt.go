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
	"os"
	"path"
	"sync"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	bboltLib "go.etcd.io/bbolt"
)

const fileMode = 0640
const bboltDbExtension = ".db"

type bboltDatabase struct {
	datadir         string
	config          BBoltConfig
	ctx             context.Context
	cancel          context.CancelFunc
	shutdownWatcher *sync.WaitGroup
}

// BBoltConfig specifies config for BBolt databases.
type BBoltConfig struct {
	// Backup specifies backup config for the database.
	Backup BBoltBackupConfig `koanf:"backup"`
}

// BBoltBackupConfig specifies config for BBolt database backups.
type BBoltBackupConfig struct {
	// Directory specifies the directory in which the BBolt backup should be written.
	Directory string `koanf:"directory"`
	// Interval specifies the time between backups.
	Interval time.Duration `koanf:"interval"`
}

// Enabled returns whether backups are enabled for BBolt.
func (b BBoltBackupConfig) Enabled() bool {
	return b.Interval > 0 && len(b.Directory) > 0
}

func createBBoltDatabase(datadir string, config BBoltConfig) (*bboltDatabase, error) {
	result := bboltDatabase{
		datadir:         datadir,
		config:          config,
		shutdownWatcher: &sync.WaitGroup{},
	}
	// Create context for initiating shutdown
	result.ctx, result.cancel = context.WithCancel(context.Background())
	return &result, nil
}

func (b bboltDatabase) createStore(moduleName string, storeName string) (stoabs.KVStore, error) {
	fullStoreName := path.Join(moduleName, storeName)
	log.Logger().
		WithField(core.LogFieldStore, fullStoreName).
		Debug("Creating BBolt store")
	databasePath := path.Join(b.datadir, fullStoreName) + bboltDbExtension
	store, err := bbolt.CreateBBoltStore(databasePath, stoabs.WithLockAcquireTimeout(lockAcquireTimeout))
	if store != nil {
		b.startBackup(fullStoreName, store)
	}
	return store, err
}

func (b bboltDatabase) getClass() Class {
	return VolatileStorageClass
}

func (b bboltDatabase) startBackup(fullStoreName string, store stoabs.KVStore) {
	if !b.config.Backup.Enabled() {
		return
	}
	interval := b.config.Backup.Interval
	log.Logger().
		WithField(core.LogFieldStore, fullStoreName).
		Infof("BBolt database will be backuped at interval of %s", interval)
	ticker := time.NewTicker(interval)

	shutdown := b.ctx.Done()
	b.shutdownWatcher.Add(1)
	go func(finished *sync.WaitGroup) {
	loop:
		for {
			select {
			case <-ticker.C:
				err := b.performBackup(fullStoreName, store)
				if err != nil {
					log.Logger().
						WithError(err).
						WithField(core.LogFieldStore, fullStoreName).
						Errorf("Unable to complete BBolt backup")
				}
			case <-shutdown:
				break loop
			}
		}
		finished.Done()
	}(b.shutdownWatcher)
}

func (b bboltDatabase) performBackup(fullStoreName string, store stoabs.KVStore) error {
	backupFilePath := path.Join(b.config.Backup.Directory, fullStoreName+bboltDbExtension)
	log.Logger().
		WithField(core.LogFieldStore, fullStoreName).
		Debugf("Starting BBolt database backup to: %s", backupFilePath)
	startTime := time.Now()
	wipFilePath := backupFilePath + ".work"
	previousFilePath := backupFilePath + ".previous"

	// To avoid corrupting the backup in case of a crash, the backup procedure looks as follows:
	// Write backup to "store.db.work"
	// Rename existing backup ("store.db") to "store.db.previous"
	// Rename "store.db.work" to "store.db"
	return store.Read(context.Background(), func(tx stoabs.ReadTx) error {
		// Make sure the parent directory exists
		err := os.MkdirAll(path.Dir(backupFilePath), os.ModePerm)
		if err != nil {
			return err
		}
		// Write backup to work file
		workFile, err := os.OpenFile(wipFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fileMode)
		defer func(f *os.File) {
			// Make sure to close file in case BBolt fails.
			_ = f.Close()
		}(workFile)
		if err != nil {
			return err
		}
		_, err = tx.Unwrap().(*bboltLib.Tx).WriteTo(workFile)
		if err != nil {
			return err
		}
		err = workFile.Close()
		if err != nil {
			return err
		}

		// Rename existing backup (if exists and not a directory)
		stat, err := os.Stat(backupFilePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			// Cannot stat
			return err
		} else if stat != nil && stat.IsDir() {
			return fmt.Errorf("backup target file is a directory: %s", backupFilePath)
		} else if stat != nil {
			err = os.Rename(backupFilePath, previousFilePath)
			if err != nil {
				return err
			}
		} // else: target file does not exist, so no need to rename to keep it
		// Rename work file to backup target file
		err = os.Rename(wipFilePath, backupFilePath)
		if err != nil {
			return err
		}
		log.Logger().
			WithField(core.LogFieldStore, fullStoreName).
			Debugf("BBolt database backup finished in %s", time.Since(startTime))
		return nil
	})
}

func (b bboltDatabase) close() {
	// Signal backup processes to stop
	b.cancel()
	// Wait for backup processes to finish
	b.shutdownWatcher.Wait()
}
