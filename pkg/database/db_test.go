package database

import (
	"os"
	"testing"
	"time"
)

func TestDatabaseIntegration(t *testing.T) {
	dbPath := "test_scoutsec.db"
	defer os.Remove(dbPath)

	// Test Initialization
	db, err := Init(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize DB: %v", err)
	}

	// Test Saving Finding
	finding := &Finding{
		CreatedAt:   time.Now(),
		Target:      "https://example.com",
		Name:        "Test Vulnerability",
		Description: "This is a test",
		Severity:    "High",
		URL:         "https://example.com/vuln",
		Evidence:    "proof",
	}

	if err := db.SaveFinding(finding); err != nil {
		t.Fatalf("Failed to save finding: %v", err)
	}

	// Test Retrieving Finding
	findings, err := db.GetFindings("https://example.com")
	if err != nil {
		t.Fatalf("Failed to get findings: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	saved := findings[0]
	if saved.Name != finding.Name {
		t.Errorf("Expected name %s, got %s", finding.Name, saved.Name)
	}
	if saved.Severity != finding.Severity {
		t.Errorf("Expected severity %s, got %s", finding.Severity, saved.Severity)
	}

	// Test Scan Progress
	target := "https://example.com"
	item := "crawl_phase"

	if db.IsScanned(target, item) {
		t.Error("Expected item to NOT be scanned yet")
	}

	if err := db.MarkScanned(target, item); err != nil {
		t.Fatalf("Failed to mark scanned: %v", err)
	}

	if !db.IsScanned(target, item) {
		t.Error("Expected item to be scanned")
	}
}
