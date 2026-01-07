package report

import (
	"encoding/csv"
	"os"
	"testing"
	"time"
)

func TestGenerateCSV(t *testing.T) {
	// Create a dummy report
	r := &Report{
		Target:   "http://example.com",
		ScanTime: time.Now(),
		ScanType: "Active",
		Issues: []Issue{
			{
				Name:        "SQL Injection",
				Description: "Possible SQL Injection",
				Severity:    "High",
				URL:         "http://example.com/id=1",
				Evidence:    "' OR 1=1--",
			},
		},
	}

	filename := "test_report.csv"
	defer os.Remove(filename)

	// Generate CSV
	if err := r.GenerateCSV(filename); err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}

	// Read and verify file content
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("Failed to open generated CSV file: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV file: %v", err)
	}

	if len(records) != 2 { // Header + 1 Row
		t.Errorf("Expected 2 records, got %d", len(records))
	}

	expectedHeader := []string{"Name", "Severity", "URL", "Description", "Evidence"}
	for i, h := range expectedHeader {
		if records[0][i] != h {
			t.Errorf("Expected header %s, got %s", h, records[0][i])
		}
	}

	if records[1][0] != "SQL Injection" {
		t.Errorf("Expected Name 'SQL Injection', got %s", records[1][0])
	}
}
