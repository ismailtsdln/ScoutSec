package analysis

import (
	"net/http"
	"testing"
)

func TestDefaultPatternsExist(t *testing.T) {
	if len(DefaultPatterns) == 0 {
		t.Error("DefaultPatterns should not be empty")
	}

	if len(DefaultPatterns) < 50 {
		t.Errorf("Expected at least 50 patterns, got %d", len(DefaultPatterns))
	}
}

func TestPatternRegex(t *testing.T) {
	// Find SQLi pattern
	var sqliPattern *Pattern
	for i := range DefaultPatterns {
		if DefaultPatterns[i].Name == "SQL Injection (Generic Payload Signature)" {
			sqliPattern = &DefaultPatterns[i]
			break
		}
	}

	if sqliPattern == nil {
		t.Fatal("SQLi pattern not found")
	}

	testCases := []struct {
		input       string
		shouldMatch bool
	}{
		{"' OR 1=1--", true},
		{"UNION SELECT", true},
		{"normal query", false},
	}

	for _, tc := range testCases {
		matches := sqliPattern.Regex.MatchString(tc.input)
		if matches != tc.shouldMatch {
			t.Errorf("Pattern %s: input '%s' should match=%v, got=%v",
				sqliPattern.Name, tc.input, tc.shouldMatch, matches)
		}
	}
}

func TestDetectorAnalyzeRequest(t *testing.T) {
	detector := NewDetector()
	req, _ := http.NewRequest("GET", "http://example.com?id=' OR 1=1--", nil)

	// This should not panic
	detector.AnalyzeRequest(req)
}

func TestSSRFPattern(t *testing.T) {
	// Find SSRF pattern
	var ssrfPattern *Pattern
	for i := range DefaultPatterns {
		if DefaultPatterns[i].Name == "SSRF (Localhost IPv4)" {
			ssrfPattern = &DefaultPatterns[i]
			break
		}
	}

	if ssrfPattern == nil {
		t.Fatal("SSRF pattern not found")
	}

	testCases := []string{
		"localhost",
		"127.0.0.1",
		"169.254.169.254",
		"metadata.google.internal",
	}

	for _, tc := range testCases {
		matched := false
		for _, p := range DefaultPatterns {
			if p.Regex.MatchString(tc) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("No pattern matched SSRF payload '%s'", tc)
		}
	}
}
