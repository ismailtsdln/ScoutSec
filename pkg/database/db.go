package database

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DB wraps the GORM database connection.
type DB struct {
	*gorm.DB
}

// Finding represents a security issue stored in the database.
type Finding struct {
	ID          uint `gorm:"primaryKey"`
	CreatedAt   time.Time
	Target      string
	Name        string
	Description string
	Severity    string
	URL         string
	Evidence    string
}

// ScanProgress tracks the status of scanned items for resume capability.
type ScanProgress struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	Target    string `gorm:"index"`
	Item      string `gorm:"index"` // URL or identifier
	Status    string
}

// Init initializes the database connection and migrates the schema.
func Init(path string) (*DB, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(&Finding{}, &ScanProgress{}); err != nil {
		return nil, err
	}

	return &DB{db}, nil
}
