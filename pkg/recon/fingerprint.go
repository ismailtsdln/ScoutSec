package recon

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// TechFingerprinter detects technologies used by a web application.
type TechFingerprinter struct {
	Client *http.Client
}

// NewTechFingerprinter creates a new technology fingerprinter.
func NewTechFingerprinter() *TechFingerprinter {
	return &TechFingerprinter{
		Client: &http.Client{},
	}
}

// Technology represents a detected technology.
type Technology struct {
	Name       string
	Version    string
	Category   string
	Confidence string
}

// Fingerprint detects technologies used by a target URL.
func (tf *TechFingerprinter) Fingerprint(url string) ([]Technology, error) {
	resp, err := tf.Client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var techs []Technology

	// Header-based detection
	techs = append(techs, tf.detectFromHeaders(resp.Header)...)

	// Body-based detection
	techs = append(techs, tf.detectFromBody(string(body))...)

	return techs, nil
}

func (tf *TechFingerprinter) detectFromHeaders(headers http.Header) []Technology {
	var techs []Technology

	// Server header
	if server := headers.Get("Server"); server != "" {
		techs = append(techs, Technology{
			Name:       server,
			Category:   "Web Server",
			Confidence: "High",
		})
	}

	// X-Powered-By
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		techs = append(techs, Technology{
			Name:       poweredBy,
			Category:   "Backend Framework",
			Confidence: "High",
		})
	}

	// X-AspNet-Version
	if aspNet := headers.Get("X-AspNet-Version"); aspNet != "" {
		techs = append(techs, Technology{
			Name:       "ASP.NET",
			Version:    aspNet,
			Category:   "Framework",
			Confidence: "High",
		})
	}

	return techs
}

func (tf *TechFingerprinter) detectFromBody(body string) []Technology {
	var techs []Technology

	// WordPress
	if strings.Contains(body, "wp-content") || strings.Contains(body, "wp-includes") {
		techs = append(techs, Technology{
			Name:       "WordPress",
			Category:   "CMS",
			Confidence: "High",
		})
	}

	// React
	if strings.Contains(body, "react") || strings.Contains(body, "__REACT") {
		techs = append(techs, Technology{
			Name:       "React",
			Category:   "JavaScript Framework",
			Confidence: "Medium",
		})
	}

	// Vue.js
	if strings.Contains(body, "Vue.js") || regexp.MustCompile(`v-[a-z]+`).MatchString(body) {
		techs = append(techs, Technology{
			Name:       "Vue.js",
			Category:   "JavaScript Framework",
			Confidence: "Medium",
		})
	}

	// Angular
	if strings.Contains(body, "ng-app") || strings.Contains(body, "angular") {
		techs = append(techs, Technology{
			Name:       "Angular",
			Category:   "JavaScript Framework",
			Confidence: "Medium",
		})
	}

	// jQuery
	if strings.Contains(body, "jquery") {
		techs = append(techs, Technology{
			Name:       "jQuery",
			Category:   "JavaScript Library",
			Confidence: "High",
		})
	}

	// Bootstrap
	if strings.Contains(body, "bootstrap") {
		techs = append(techs, Technology{
			Name:       "Bootstrap",
			Category:   "CSS Framework",
			Confidence: "High",
		})
	}

	return techs
}

// PrintTechnologies displays detected technologies.
func PrintTechnologies(techs []Technology) {
	fmt.Println("\n[Tech Stack Detection]")
	for _, tech := range techs {
		version := tech.Version
		if version == "" {
			version = "unknown"
		}
		fmt.Printf("  [%s] %s (v%s) - Confidence: %s\n",
			tech.Category, tech.Name, version, tech.Confidence)
	}
}
