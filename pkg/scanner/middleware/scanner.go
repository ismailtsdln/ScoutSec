package middleware

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// Fingerprint represents a signature for a middleware.
type Fingerprint struct {
	Name        string
	Path        string // Default path to check (e.g., /manager/html)
	MatchString string // String to look for in response body
	Description string
	Severity    string
}

// DefaultFingerprints returns a list of common middleware fingerprints.
func DefaultFingerprints() []Fingerprint {
	return []Fingerprint{
		{
			Name:        "Apache Tomcat Manager",
			Path:        "/manager/html",
			MatchString: "Tomcat Web Application Manager",
			Description: "Tomcat Manager Application exposed",
			Severity:    "High",
		},
		{
			Name:        "Jenkins",
			Path:        "/login",
			MatchString: "Jenkins",
			Description: "Jenkins Login Page exposed",
			Severity:    "Info",
		},
		{
			Name:        "Axis2 Web Admin",
			Path:        "/axis2/axis2-admin",
			MatchString: "Axis2 Administration",
			Description: "Apache Axis2 Administration Console exposed",
			Severity:    "High",
		},
		{
			Name:        "JBoss Web Console",
			Path:        "/jmx-console/",
			MatchString: "JBoss JMX Console",
			Description: "JBoss JMX Console exposed",
			Severity:    "Critical",
		},
		{
			Name:        "Actuator Info",
			Path:        "/actuator/info",
			MatchString: "git",
			Description: "Spring Boot Actuator Info exposed (potential leak)",
			Severity:    "Low",
		},
		{
			Name:        "Actuator Heapdump",
			Path:        "/actuator/heapdump",
			MatchString: "JAVA_PROFILE", // Heuristic match for heapdump binary header
			Description: "Spring Boot Actuator Heapdump exposed (Sensitive Data Leak)",
			Severity:    "Critical",
		},
		{
			Name:        "WordPress Login",
			Path:        "/wp-login.php",
			MatchString: "Powered by WordPress",
			Description: "WordPress Login Page",
			Severity:    "Info",
		},
	}
}

// Scanner scans for middleware vulnerabilities.
type Scanner struct {
	Target string
	Client *http.Client
}

// NewScanner creates a new Middleware Scanner.
func NewScanner(target string) *Scanner {
	return &Scanner{
		Target: target,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start begins the middleware scan.
func (s *Scanner) Start() {
	fmt.Println("[*] Starting Middleware Scan...")
	fps := DefaultFingerprints()
	var wg sync.WaitGroup

	for _, fp := range fps {
		wg.Add(1)
		go s.checkFingerprint(fp, &wg)
	}

	wg.Wait()
	fmt.Println("[✓] Middleware Scan completed.")
}

func (s *Scanner) checkFingerprint(fp Fingerprint, wg *sync.WaitGroup) {
	defer wg.Done()

	// Normalize target URL
	url := strings.TrimRight(s.Target, "/") + fp.Path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		body := string(bodyBytes)

		if strings.Contains(body, fp.MatchString) {
			msg := fmt.Sprintf("Found %s at %s", fp.Name, url)
			fmt.Println("[!] " + msg)

			report.AddIssue(report.Issue{
				Name:        "Middleware Detected: " + fp.Name,
				Description: fp.Description,
				Severity:    fp.Severity,
				URL:         url,
				Evidence:    fmt.Sprintf("Matched string '%s' at %s", fp.MatchString, url),
			})
		}
	}
}
