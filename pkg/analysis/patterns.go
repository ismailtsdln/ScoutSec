package analysis

import (
	"regexp"
)

// Pattern represents a vulnerability detection pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Description string
	Risk        string // High, Medium, Low
}

var DefaultPatterns = []Pattern{
	// SQL Injection
	{
		Name:        "SQL Injection (Error Based)",
		Regex:       regexp.MustCompile(`(?i)(SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient\.|ORA-\d+|PostgreSQL.*ERROR|SQLite.*error)`),
		Description: "Potential SQL error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Generic)",
		Regex:       regexp.MustCompile(`(?i)(OR 1=1|UNION SELECT|'--|#|%27|sleep\(|benchmark\(|waitfor delay)`),
		Description: "Common SQL Injection payload signature",
		Risk:        "High",
	},

	// Path Traversal
	{
		Name:        "LFI / Path Traversal",
		Regex:       regexp.MustCompile(`(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|c:\\windows\\win\.ini|\.\.%2F|%2e%2e%2f)`),
		Description: "Potential Path Traversal or LFI pattern",
		Risk:        "High",
	},

	// XSS
	{
		Name:        "Reflected XSS",
		Regex:       regexp.MustCompile(`(?i)(<script>|<img.*onerror|<svg.*onload|javascript:|on\w+\s*=)`),
		Description: "Potential XSS payload reflected",
		Risk:        "High",
	},

	// SSRF
	{
		Name:        "Server-Side Request Forgery (SSRF)",
		Regex:       regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|169\.254\.169\.254|metadata\.google\.internal)`),
		Description: "Potential SSRF attempt to internal resources",
		Risk:        "High",
	},

	// XXE
	{
		Name:        "XML External Entity (XXE)",
		Regex:       regexp.MustCompile(`(?i)(<!ENTITY|<!DOCTYPE.*SYSTEM|<!ELEMENT)`),
		Description: "Potential XXE payload in XML",
		Risk:        "High",
	},

	// Command Injection
	{
		Name:        "Command Injection",
		Regex:       regexp.MustCompile(`(?i)(;.*ls|;.*cat|;.*whoami|\|.*nc|\$\(.*\)|` + "`" + `.*` + "`" + `)`),
		Description: "Potential OS command injection",
		Risk:        "Critical",
	},

	// Info Disclosure
	{
		Name:        "Sensitive Info Leak (AWS Key)",
		Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Description: "Potential AWS Access Key ID leaked",
		Risk:        "Critical",
	},
	{
		Name:        "Sensitive Info Leak (Private Key)",
		Regex:       regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
		Description: "Private key exposed",
		Risk:        "Critical",
	},
	{
		Name:        "Sensitive Info Leak (API Keys)",
		Regex:       regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?token).*[:=]\s*['"]\w{20,}['"]`),
		Description: "Potential API key or token exposed",
		Risk:        "High",
	},

	// Open Redirect
	{
		Name:        "Open Redirect",
		Regex:       regexp.MustCompile(`(?i)(redirect|return|url|next|continue)=http`),
		Description: "Potential open redirect vulnerability",
		Risk:        "Medium",
	},

	// CSRF
	{
		Name:        "Missing CSRF Token",
		Regex:       regexp.MustCompile(`<form[^>]*>`),
		Description: "Form without visible CSRF protection",
		Risk:        "Medium",
	},

	// CRLF Injection
	{
		Name:        "CRLF Injection",
		Regex:       regexp.MustCompile(`(%0d%0a|%0a%0d|\\r\\n|\\n\\r)`),
		Description: "Potential CRLF injection (HTTP response splitting)",
		Risk:        "Medium",
	},
}
