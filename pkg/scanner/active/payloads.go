package active

// Payload represents a test case for active scanning.
type Payload struct {
	Name    string
	Content string
	Type    string // e.g., SQLi, XSS
}

// GetDefaultPayloads returns a list of common security payloads.
func GetDefaultPayloads() []Payload {
	return []Payload{
		{"Basic XSS", "<script>alert(1)</script>", "XSS"},
		{"SQLi Boolean", "' OR 1=1--", "SQLi"},
		{"SQLi Union", "' UNION SELECT 1,2,3--", "SQLi"},
		{"LFI Basic", "../../../../etc/passwd", "LFI"},
		{"Command Injection", "; ls -la", "CMDi"},
	}
}
