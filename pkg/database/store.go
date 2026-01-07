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

// MarkScanned records an item as scanned.
func (db *DB) MarkScanned(target, item string) error {
	if db == nil {
		return nil // No-op if DB disabled
	}
	progress := ScanProgress{
		Target: target,
		Item:   item,
		Status: "scanned",
	}
	return db.FirstOrCreate(&progress, ScanProgress{Target: target, Item: item}).Error
}

// IsScanned checks if an item has already been scanned.
func (db *DB) IsScanned(target, item string) bool {
	if db == nil {
		return false
	}
	var count int64
	db.Model(&ScanProgress{}).Where("target = ? AND item = ? AND status = ?", target, item, "scanned").Count(&count)
	return count > 0
}

// GetAllFindings retrieves all findings from the database.
func (db *DB) GetAllFindings() ([]Finding, error) {
	var findings []Finding
	if err := db.Order("created_at desc").Find(&findings).Error; err != nil {
		return nil, err
	}
	return findings, nil
}
