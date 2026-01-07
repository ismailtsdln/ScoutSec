package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// Scanner handles API fuzzing based on OpenAPI specs.
type Scanner struct {
	SpecURL string
	Client  *http.Client
	Report  *report.Report
}

// NewScanner creates a new API Scanner.
func NewScanner(specURL string, rep *report.Report) *Scanner {
	return &Scanner{
		SpecURL: specURL,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		Report: rep,
	}
}

// Start begins the API fuzzing process.
func (s *Scanner) Start() {
	fmt.Printf("[*] Starting API Fuzzing using spec: %s\n", s.SpecURL)

	ctx := context.Background()
	loader := openapi3.NewLoader()

	// Load spec from URL or file
	doc, err := loader.LoadFromURI(func() *url.URL {
		u, _ := url.Parse(s.SpecURL)
		return u
	}())

	if err != nil {
		fmt.Printf("Error loading OpenAPI spec: %v\n", err)
		return
	}

	if err := doc.Validate(ctx); err != nil {
		fmt.Printf("Warning: OpenAPI spec validation failed: %v\n", err)
	}

	baseURL := s.SpecURL // Default to spec URL base
	if len(doc.Servers) > 0 {
		baseURL = doc.Servers[0].URL
		fmt.Printf("Base URL found in spec: %s\n", baseURL)
	}

	// Iterate over paths which is a map in newer versions or struct with Map()
	for path, pathItem := range doc.Paths.Map() {
		for method, op := range pathItem.Operations() {
			fmt.Printf("Fuzzing %s %s...\n", method, path)
			s.fuzzEndpoint(baseURL, path, method, op)
		}
	}

	fmt.Println("[✓] API Fuzzing completed.")
}

func (s *Scanner) fuzzEndpoint(baseURL, path, method string, op *openapi3.Operation) {
	// Simple fuzzing strategy: Replace path parameters and query parameters with payloads

	// Target URL construction (simplified)
	targetURL := baseURL + path
	if !strings.HasPrefix(targetURL, "http") {
		// If baseURL is relative, assuming it's relative to the spec location might be tricky without full resolution logic.
		// For now, assume absolute or handle simple join.
		// A robust implementation would resolve regex against the spec location.
		// Fallback for demo:
		parsedSpec, _ := url.Parse(s.SpecURL)
		targetURL = fmt.Sprintf("%s://%s%s", parsedSpec.Scheme, parsedSpec.Host, path)
	}

	// 1. Test for SQL Injection in Query Params
	payloads := []string{"'", "\"", "1 OR 1=1"}

	// Check parameters
	for _, paramRef := range op.Parameters {
		param := paramRef.Value
		if param.In == "query" {
			for _, p := range payloads {
				// Construct URL with payload
				fuzzURL := targetURL + fmt.Sprintf("?%s=%s", param.Name, url.QueryEscape(p))

				req, _ := http.NewRequest(method, fuzzURL, nil)
				resp, err := s.Client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode == 500 {
					fmt.Printf("[!] Possible SQLi in %s param %s with payload %s\n", method, param.Name, p)
					issue := report.Issue{
						Name:        "Possible API SQL Injection",
						Description: fmt.Sprintf("500 Error triggered by SQLi payload in param %s", param.Name),
						Severity:    "High",
						URL:         fuzzURL,
						Evidence:    fmt.Sprintf("Payload: %s triggered 500 Internal Server Error", p),
					}
					if s.Report != nil {
						s.Report.AddIssue(issue)
					} else {
						report.AddIssue(issue)
					}
				}
			}
		}
	}
}
