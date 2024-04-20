/*
 * Copyright (C) 2024 Nuts community
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
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"strings"
	"sync"
	"time"
)

var _ SessionDatabase = (*sqlSessionDatabase)(nil)

var _ schema.Tabler = (*sessionStoreRecord)(nil)

type sessionStoreRecord struct {
	Store   string `gorm:"primaryKey"`
	Key     string `gorm:"primaryKey"`
	Expires int
	Value   string
}

func (s sessionStoreRecord) TableName() string {
	return "session_store"
}

var sqlSessionPruneInterval = time.Minute

func NewSQLSessionDatabase(db *gorm.DB) SessionDatabase {
	result := sqlSessionDatabase{
		db:       db,
		routines: &sync.WaitGroup{},
	}
	result.ctx, result.cancel = context.WithCancel(context.Background())
	result.startPruning()
	return result
}

type sqlSessionDatabase struct {
	db       *gorm.DB
	routines *sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

func (s sqlSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	return sqlSessionStore{
		db:        s.db,
		ttl:       ttl,
		storeName: strings.Join(keys, "."),
	}
}

func (s sqlSessionDatabase) close() {
	s.cancel()
	s.routines.Wait()
}

func (s sqlSessionDatabase) startPruning() {
	s.routines.Add(1)
	go func() {
		defer s.routines.Done()
		for {
			select {
			case <-time.After(sqlSessionPruneInterval):
				if err := s.db.Exec("DELETE FROM session_store WHERE expires <= ?", time.Now().Unix()).Error; err != nil {
					log.Logger().WithError(err).Warnf("SQL session store startPruning failed")
				}
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

type sqlSessionStore struct {
	db        *gorm.DB
	ttl       time.Duration
	storeName string
}

func (s sqlSessionStore) Delete(key string) error {
	return s.db.Model(&sessionStoreRecord{}).Where("store = ? AND key = ?", s.storeName, key).Delete(&sessionStoreRecord{}).Error
}

func (s sqlSessionStore) Exists(key string) bool {
	var count int64
	s.db.Model(&sessionStoreRecord{}).Where("store = ? AND key = ? AND expires > ?", s.storeName, key, time.Now().Unix()).Count(&count)
	return count > 0
}

func (s sqlSessionStore) Get(key string, target interface{}) error {
	var record sessionStoreRecord
	err := s.db.Model(&sessionStoreRecord{}).Where("store = ? AND key = ?", s.storeName, key).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if time.Now().After(time.Unix(int64(record.Expires), 0)) {
		return ErrNotFound
	}
	return json.Unmarshal([]byte(record.Value), target)
}

func (s sqlSessionStore) Put(key string, value interface{}) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	record := sessionStoreRecord{
		Store:   s.storeName,
		Expires: int(time.Now().Add(s.ttl).Unix()),
		Key:     key,
		Value:   string(bytes),
	}
	// Create or Update
	return s.db.Model(&sessionStoreRecord{}).
		Where("store = ? AND key = ?", s.storeName, key).
		Assign(record).
		FirstOrCreate(&record).Error
}
