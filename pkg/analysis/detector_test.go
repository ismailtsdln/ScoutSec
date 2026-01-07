package analysis

import (
	"net/http"
	"testing"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

func TestDetector_AnalyzeRequest(t *testing.T) {
	// Initialize report system
	report.InitReport("test.com", "Test")

	detector := NewDetector()
	req, _ := http.NewRequest("GET", "http://example.com?id=' OR 1=1--", nil)

	detector.AnalyzeRequest(req)
	// Ideally we'd mock the report.AddIssue logic or check the global report store.
	// Since we used a global store, we can check it.

	if len(report.GlobalReport.Issues) == 0 {
		t.Errorf("Expected issue to be detected for SQLi payload")
	}
}
