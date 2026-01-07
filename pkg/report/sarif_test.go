package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGenerateSARIF(t *testing.T) {
	// Create a dummy report
	r := &Report{
		Target:   "http://example.com",
		ScanTime: time.Now(),
		ScanType: "Active",
		Issues: []Issue{
			{
				Name:        "SQL Injection",
				Description: "Possible SQL Injection vulnerability",
				Severity:    "High",
				URL:         "http://example.com/id=1",
				Evidence:    "' OR 1=1--",
			},
			{
				Name:        "XSS",
				Description: "Reflected Cross-Site Scripting",
				Severity:    "Medium",
				URL:         "http://example.com/q=<script>",
				Evidence:    "<script>alert(1)</script>",
			},
		},
	}

	filename := "test_report.sarif"
	defer os.Remove(filename)

	// Generate SARIF
	if err := r.GenerateSARIF(filename); err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	// Read and verify file content
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read generated SARIF file: %v", err)
	}

	var sarif SarifLog
	if err := json.Unmarshal(content, &sarif); err != nil {
		t.Fatalf("Generated SARIF is not valid JSON: %v", err)
	}

	// Check Version
	if sarif.Version != "2.1.0" {
		t.Errorf("Expected version 2.1.0, got %s", sarif.Version)
	}

	// Check Runs
	if len(sarif.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(sarif.Runs))
	}
	run := sarif.Runs[0]

	// Check Tool Driver
	if run.Tool.Driver.Name != "ScoutSec" {
		t.Errorf("Expected tool name ScoutSec, got %s", run.Tool.Driver.Name)
	}

	// Check Results
	if len(run.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(run.Results))
	}

	// Check Rule ID presence
	foundSQLi := false
	for _, res := range run.Results {
		if res.RuleID == "SQL Injection" {
			foundSQLi = true
			if res.Level != "error" {
				t.Errorf("Expected SQLi level to be error, got %s", res.Level)
			}
		}
	}

	if !foundSQLi {
		t.Error("SQL Injection result not found in SARIF")
	}

	// Check Rules Definitions
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("Expected 2 rules definitions, got %d", len(run.Tool.Driver.Rules))
	}

	// Check content for string presence
	strContent := string(content)
	if !strings.Contains(strContent, "http://example.com/id=1") {
		t.Error("Target URL not found in SARIF content")
	}
}
