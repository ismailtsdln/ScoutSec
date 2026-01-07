package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SubdomainEnumerator handles subdomain discovery.
type SubdomainEnumerator struct {
	Client *http.Client
}

// NewSubdomainEnumerator creates a new subdomain enumerator.
func NewSubdomainEnumerator() *SubdomainEnumerator {
	return &SubdomainEnumerator{
		Client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// EnumeratePassive performs passive subdomain enumeration using public APIs.
func (se *SubdomainEnumerator) EnumeratePassive(domain string) ([]string, error) {
	var subdomains []string

	// Use crt.sh certificate transparency logs
	crtSubdomains, err := se.queryCrtSh(domain)
	if err == nil {
		subdomains = append(subdomains, crtSubdomains...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := []string{}
	for _, sub := range subdomains {
		if !seen[sub] {
			seen[sub] = true
			unique = append(unique, sub)
		}
	}

	return unique, nil
}

func (se *SubdomainEnumerator) queryCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	resp, err := se.Client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, r := range results {
		subdomains = append(subdomains, r.NameValue)
	}

	return subdomains, nil
}

// EnumerateActive performs active subdomain bruteforcing.
func (se *SubdomainEnumerator) EnumerateActive(domain string, wordlist []string) []string {
	var found []string

	for _, word := range wordlist {
		subdomain := fmt.Sprintf("%s.%s", word, domain)

		// Simple DNS resolution check
		resp, err := se.Client.Get(fmt.Sprintf("http://%s", subdomain))
		if err == nil {
			resp.Body.Close()
			found = append(found, subdomain)
			fmt.Printf("[+] Found: %s\n", subdomain)
		}
	}

	return found
}

// GetCommonWordlist returns a basic subdomain wordlist.
func GetCommonWordlist() []string {
	return []string{
		"www", "mail", "ftp", "admin", "webmail", "portal",
		"api", "dev", "staging", "test", "beta", "vpn",
		"blog", "shop", "store", "cdn", "assets", "static",
	}
}
