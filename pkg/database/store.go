package database

import "fmt"

// SaveFinding persists a finding to the database.
func (db *DB) SaveFinding(finding *Finding) error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}
	return db.Create(finding).Error
}

// GetFindings retrieves all findings for a given target.
func (db *DB) GetFindings(target string) ([]Finding, error) {
	var findings []Finding
	if err := db.Where("target = ?", target).Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}
