package storage

type tenantRecord struct {
	ID string `gorm:"primaryKey"`
}

type tenantDID struct {
	ID string `gorm:"primaryKey"`
}

type SQLStore struct {
}
