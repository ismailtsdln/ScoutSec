package report

import (
	"os"
	"testing"
	"time"
)

func TestGeneratePDF(t *testing.T) {
	r := &Report{
		Target:   "https://example.com",
		ScanTime: time.Now(),
		ScanType: "Active",
		Issues: []Issue{
			{
				Name:        "SQL Injection",
				Severity:    "Critical",
				URL:         "https://example.com/id=1'",
				Description: "Possible SQL injection vulnerability.",
				Evidence:    "Error: syntax error",
			},
			{
				Name:        "XSS",
				Severity:    "High",
				URL:         "https://example.com/q=<script>",
				Description: "Reflected XSS.",
				Evidence:    "<script>alert(1)</script>",
			},
		},
	}

	filename := "test_report.pdf"
	defer os.Remove(filename)

	if err := r.GeneratePDF(filename); err != nil {
		t.Fatalf("Failed to generate PDF: %v", err)
	}

	// Verify file exists and has size > 0
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("PDF file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("PDF file is empty")
	}
}
