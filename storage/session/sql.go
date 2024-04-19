package session

import (
	"encoding/json"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"strings"
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

type sqlSessionDatabase struct {
	db *gorm.DB
}

func (s sqlSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	return sqlSessionStore{
		db:        s.db,
		ttl:       ttl,
		storeName: strings.Join(keys, "."),
	}
}

func (s sqlSessionDatabase) Close() {
	// Noop
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
	s.db.Model(&sessionStoreRecord{}).Where("store = ? AND key = ?", s.storeName, key).Count(&count)
	return count > 0
}

func (s sqlSessionStore) Get(key string, target interface{}) error {
	var record sessionStoreRecord
	if err := s.db.Model(&sessionStoreRecord{}).Where("store = ? AND key = ?", s.storeName, key).First(&record).Error; err != nil {
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
	return s.db.Model(&sessionStoreRecord{}).Save(&record).Error
}
