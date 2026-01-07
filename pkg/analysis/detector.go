package analysis

import (
	"log"
	"net/http"
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

// AnalyzeResponse checks an HTTP response for vulnerabilities.
func (d *Detector) AnalyzeResponse(resp *http.Response) {
	// Example: Check headers for security misconfigurations
	if resp.Header.Get("X-Frame-Options") == "" {
		log.Printf("[VULN] Missing X-Frame-Options header in response from %s", resp.Request.URL)
	}
}

func (d *Detector) checkPatterns(key, value, context string) {
	for _, p := range d.Patterns {
		if p.Regex.MatchString(value) {
			log.Printf("[VULN] Possible %s detected in %s (%s=%s)", p.Name, context, key, value)
		}
	}
}

// Normalize checks to avoid nil pointers
func safeGetHeader(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	return h.Get(key)
}
