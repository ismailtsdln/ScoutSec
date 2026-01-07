package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// Fuzzer handles API fuzzing operations.
type Fuzzer struct {
	BaseURL string
	Client  *http.Client
}

// NewAPIFuzzer creates a new API fuzzer.
func NewAPIFuzzer(baseURL string) *Fuzzer {
	return &Fuzzer{
		BaseURL: baseURL,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// FuzzEndpoint fuzzes a single API endpoint with test payloads.
func (f *Fuzzer) FuzzEndpoint(endpoint Endpoint) {
	fmt.Printf("[API] Fuzzing %s %s\n", endpoint.Method, endpoint.Path)

	// Test for BOLA/IDOR
	f.testBOLA(endpoint)

	// Test for JSON Injection
	f.testJSONInjection(endpoint)
}

func (f *Fuzzer) testBOLA(endpoint Endpoint) {
	// BOLA test: try accessing with different IDs
	testIDs := []string{"1", "999", "../admin", "null"}

	for _, id := range testIDs {
		// Replace {id} or similar path params
		testPath := endpoint.Path
		// For simplicity, we'll append as query param if no path param found
		url := f.BaseURL + testPath + "?id=" + id

		req, _ := http.NewRequest(endpoint.Method, url, nil)
		resp, err := f.Client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for suspicious access (e.g., 200 OK on different user IDs)
		if resp.StatusCode == 200 {
			report.AddIssue(report.Issue{
				Name:        "Potential BOLA/IDOR",
				Description: fmt.Sprintf("Endpoint %s may be vulnerable to BOLA", endpoint.Path),
				Severity:    "High",
				URL:         url,
				Evidence:    fmt.Sprintf("ID=%s returned 200 OK", id),
			})
		}
	}
}

func (f *Fuzzer) testJSONInjection(endpoint Endpoint) {
	// Test JSON injection payloads
	payload := map[string]interface{}{
		"test": "' OR 1=1--",
		"eval": "<script>alert(1)</script>",
	}

	jsonData, _ := json.Marshal(payload)
	url := f.BaseURL + endpoint.Path

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Basic check: if server reflects input without validation
	// This is simplified; real detection would parse response
	if resp.StatusCode >= 500 {
		report.AddIssue(report.Issue{
			Name:        "Potential JSON Injection",
			Description: "Server returned 5xx when processing test payload",
			Severity:    "Medium",
			URL:         url,
			Evidence:    string(jsonData),
		})
	}
}
