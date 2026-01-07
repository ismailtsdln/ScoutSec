package analysis

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// Detector analyzes HTTP traffic for vulnerabilities.
type Detector struct {
	Patterns []Pattern
}

// NewDetector creates a new Detector with default patterns.
func NewDetector() *Detector {
	return &Detector{
		Patterns: DefaultPatterns,
	}
}

// AnalyzeRequest checks an HTTP request for vulnerabilities.
func (d *Detector) AnalyzeRequest(req *http.Request) {
	// Example: Check query parameters for suspicious patterns
	queryParams := req.URL.Query()
	for param, values := range queryParams {
		for _, value := range values {
			d.checkPatterns(param, value, "Request Parameter")
		}
	}
}

// AnalyzeResponse checks an HTTP response for vulnerabilities and misconfigurations.
func (d *Detector) AnalyzeResponse(resp *http.Response) {
	d.checkWAF(resp)
	d.auditSecurityHeaders(resp)
}

func (d *Detector) checkWAF(resp *http.Response) {
	wafHeaders := map[string]string{
		"X-Powered-By": "WAF",
		"Server":       "Cloudflare",
		"X-Cloud-Edge": "WAF",
		"X-Akamai":     "Akamai",
	}

	for header, provider := range wafHeaders {
		if resp.Header.Get(header) != "" {
			log.Printf("[INFO] Possible WAF detected (%s): %s", provider, resp.Header.Get(header))
		}
	}

	// Check for common WAF status codes
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		log.Printf("[INFO] Possible WAF protection triggered (Status %d)", resp.StatusCode)
	}
}

func (d *Detector) auditSecurityHeaders(resp *http.Response) {
	headersToAudit := []struct {
		Name     string
		Severity string
	}{
		{"X-Frame-Options", "Medium"},
		{"Content-Security-Policy", "High"},
		{"Strict-Transport-Security", "Medium"},
		{"X-Content-Type-Options", "Low"},
		{"Referrer-Policy", "Low"},
	}

	for _, h := range headersToAudit {
		if resp.Header.Get(h.Name) == "" {
			report.AddIssue(report.Issue{
				Name:        fmt.Sprintf("Missing Security Header: %s", h.Name),
				Description: fmt.Sprintf("The server is not sending the %s header, which exposes the application to various attacks.", h.Name),
				Severity:    h.Severity,
				URL:         resp.Request.URL.String(),
				Evidence:    fmt.Sprintf("Host: %s", resp.Request.Host),
			})
		}
	}
}

func (d *Detector) checkPatterns(key, value, context string) {
	for _, p := range d.Patterns {
		if p.Regex.MatchString(value) {
			log.Printf("[VULN] Possible %s detected in %s (%s=%s)", p.Name, context, key, value)
			report.AddIssue(report.Issue{
				Name:        p.Name,
				Description: p.Description,
				Severity:    p.Risk,
				URL:         context, // Using context as URL placeholder for now
				Evidence:    fmt.Sprintf("Key: %s, Value: %s", key, value),
			})
		}
	}
}
