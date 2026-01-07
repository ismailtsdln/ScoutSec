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
	{
		Name:        "SQL Injection (Error Based)",
		Regex:       regexp.MustCompile(`(?i)(SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient\.)`),
		Description: "Potential SQL error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Generic)",
		Regex:       regexp.MustCompile(`(?i)(OR 1=1|UNION SELECT|'--|#)`),
		Description: "Common SQL Injection payload signature",
		Risk:        "Medium",
	},
	{
		Name:        "LFI / Path Traversal",
		Regex:       regexp.MustCompile(`(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|c:\\windows\\win.ini)`),
		Description: "Potential Path Traversal or LFI pattern",
		Risk:        "High",
	},
	{
		Name:        "Reflected XSS (Simple)",
		Regex:       regexp.MustCompile(`(?i)<script>alert\(1\)</script>`),
		Description: "Simple XSS payload reflected (very basic)",
		Risk:        "Medium",
	},
	{
		Name:        "Sensitive Info Leak (AWS Key)",
		Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Description: "Potential AWS Access Key ID leaked",
		Risk:        "High",
	},
}
