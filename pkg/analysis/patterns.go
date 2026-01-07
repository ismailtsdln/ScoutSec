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
	// --- SQL Injection (SQLi) ---
	{
		Name:        "SQL Injection (Error Based - MySQL)",
		Regex:       regexp.MustCompile(`(?i)(SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlClient\.)`),
		Description: "MySQL error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Error Based - PostgreSQL)",
		Regex:       regexp.MustCompile(`(?i)(PostgreSQL.*ERROR|Warning.*\Wpg_.*|valid PostgreSQL result|Npgsql\.)`),
		Description: "PostgreSQL error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Error Based - MSSQL)",
		Regex:       regexp.MustCompile(`(?i)(Driver.* SQL[\-\_\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|Exception.*\bRoadhouse\b)`),
		Description: "Microsoft SQL Server error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Error Based - Oracle)",
		Regex:       regexp.MustCompile(`(?i)(ORA-[0-9][0-9][0-9][0-9]|Oracle error|Oracle.*Driver|Warning.*\Woci_.*|Warning.*\Wora_.*)`),
		Description: "Oracle SQL error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Error Based - SQLite)",
		Regex:       regexp.MustCompile(`(?i)(SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::)`),
		Description: "SQLite error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Error Based - ODBC/Generic)",
		Regex:       regexp.MustCompile(`(?i)(ODBC SQL Server Driver|ODBC Driver|Microsoft Access Driver|CLI Driver.*DB2|DB2 SQL error)`),
		Description: "Generic/ODBC SQL error message detected",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Generic Payload Signature)",
		Regex:       regexp.MustCompile(`(?i)(\bOR\s+['"]?1['"]?\s*=\s*['"]?1|'--|#|/\*|;\s*DROP\s+TABLE|UNION\s+ALL\s+SELECT|UNION\s+SELECT)`),
		Description: "Common SQL Injection payload signature",
		Risk:        "High",
	},
	{
		Name:        "SQL Injection (Time Based)",
		Regex:       regexp.MustCompile(`(?i)(sleep\(\d+\)|benchmark\(\d+,\w+\)|pg_sleep\(\d+\)|waitfor delay|dbms_pipe\.receive_message)`),
		Description: "Potential time-based SQL injection",
		Risk:        "High",
	},

	// --- Cross-Site Scripting (XSS) ---
	{
		Name:        "Reflected XSS (Script Tag)",
		Regex:       regexp.MustCompile(`(?i)(<script[^>]*>[\s\S]*?</script>|<script\b)`),
		Description: "Potential XSS via script tag",
		Risk:        "High",
	},
	{
		Name:        "Reflected XSS (Event Handlers)",
		Regex:       regexp.MustCompile(`(?i)(on\w+\s*=\s*['"][^'"]*alert|on\w+\s*=\s*['"][^'"]*prompt|on\w+\s*=\s*['"][^'"]*confirm)`),
		Description: "Potential XSS via event handler (onload, onerror, etc.)",
		Risk:        "High",
	},
	{
		Name:        "Reflected XSS (Javascript Protocol)",
		Regex:       regexp.MustCompile(`(?i)(href\s*=\s*['"]javascript:|action\s*=\s*['"]javascript:)`),
		Description: "Potential XSS via javascript: protocol",
		Risk:        "High",
	},
	{
		Name:        "Reflected XSS (SVG/IMG)",
		Regex:       regexp.MustCompile(`(?i)(<img[^>]+onerror|<svg[^>]+onload|<iframe[^>]+onload)`),
		Description: "Potential XSS via SVG/IMG/IFRAME tags",
		Risk:        "High",
	},
	{
		Name:        "XSS (Polyglot Signature)",
		Regex:       regexp.MustCompile(`(?i)(javascript:\/\/|jaVasCript:|expression\()`),
		Description: "Potential obfuscated/polyglot XSS",
		Risk:        "High",
	},

	// --- Path Traversal / LFI ---
	{
		Name:        "LFI / Path Traversal (Basic)",
		Regex:       regexp.MustCompile(`(?i)(\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f)`),
		Description: "Directory traversal detected (../)",
		Risk:        "High",
	},
	{
		Name:        "LFI (System Files - Linux)",
		Regex:       regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/group|/etc/hosts|/proc/self/environ)`),
		Description: "Sensitive Linux system file path detected",
		Risk:        "Critical",
	},
	{
		Name:        "LFI (System Files - Windows)",
		Regex:       regexp.MustCompile(`(?i)(c:\\windows\\win\.ini|c:\\windows\\system32|c:\\boot\.ini)`),
		Description: "Sensitive Windows system file path detected",
		Risk:        "Critical",
	},
	{
		Name:        "LFI (Wrappers)",
		Regex:       regexp.MustCompile(`(?i)(php://filter|php://input|data://|zip://|expect://)`),
		Description: "PHP wrapper usage detected (potential LFI/RCE)",
		Risk:        "High",
	},

	// --- Server-Side Request Forgery (SSRF) ---
	{
		Name:        "SSRF (Localhost IPv4)",
		Regex:       regexp.MustCompile(`(127\.0\.0\.1|0\.0\.0\.0)`),
		Description: "Potential SSRF to localhost (IPv4)",
		Risk:        "High",
	},
	{
		Name:        "SSRF (Localhost IPv6)",
		Regex:       regexp.MustCompile(`(::1|0:0:0:0:0:0:0:1)`),
		Description: "Potential SSRF to localhost (IPv6)",
		Risk:        "High",
	},
	{
		Name:        "SSRF (Cloud Metadata - AWS/GCP/Azure)",
		Regex:       regexp.MustCompile(`(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`),
		Description: "Potential SSRF to Cloud Metadata Service",
		Risk:        "Critical",
	},
	{
		Name:        "SSRF (Private IP Ranges)",
		Regex:       regexp.MustCompile(`(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})`),
		Description: "Potential SSRF to private internal network",
		Risk:        "High",
	},

	// --- XML External Entity (XXE) ---
	{
		Name:        "XXE (Entity Definition)",
		Regex:       regexp.MustCompile(`(?i)(<!ENTITY\s+\w+\s+SYSTEM|<!ENTITY\s+\w+\s+PUBLIC)`),
		Description: "External Entity definition detected",
		Risk:        "High",
	},
	{
		Name:        "XXE (Specific Payloads)",
		Regex:       regexp.MustCompile(`(?i)(<!DOCTYPE.*SYSTEM|<!ELEMENT)`),
		Description: "Potential XXE payload structure",
		Risk:        "High",
	},

	// --- Command Injection (RCE) ---
	{
		Name:        "Command Injection (Unix)",
		Regex:       regexp.MustCompile(`(?i)(;.*ls|;.*cat|;.*id|;.*whoami|\|.*nc|\|.*netcat|\|.*wget|\|.*curl|\$\(.*\)|` + "`" + `.*` + "`" + `)`),
		Description: "Potential Unix OS command injection",
		Risk:        "Critical",
	},
	{
		Name:        "Command Injection (Windows)",
		Regex:       regexp.MustCompile(`(?i)(&.*dir|&.*ipconfig|&.*net user|\|.*ver)`),
		Description: "Potential Windows OS command injection",
		Risk:        "Critical",
	},
	{
		Name:        "RCE (Language Specific)",
		Regex:       regexp.MustCompile(`(?i)(eval\(|system\(|passthru\(|exec\(|popen\(|proc_open\()`),
		Description: "Potential Remote Code Execution via dangerous functions",
		Risk:        "Critical",
	},

	// --- Information Disclosure (Secrets & Keys) ---
	{
		Name:        "AWS Access Key ID",
		Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Description: "Potential AWS Access Key ID leaked",
		Risk:        "Critical",
	},
	{
		Name:        "AWS Secret Access Key",
		Regex:       regexp.MustCompile(`(?i)(aws_?secret_?access_?key|aws_?key).*['"]?[0-9a-zA-Z\/+]{40}['"]?`),
		Description: "Potential AWS Secret Access Key leaked",
		Risk:        "Critical",
	},
	{
		Name:        "Private SSH/RSA Key",
		Regex:       regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----`),
		Description: "Private cryptographic key exposed",
		Risk:        "Critical",
	},
	{
		Name:        "Google API Key",
		Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		Description: "Google API Key exposed",
		Risk:        "High",
	},
	{
		Name:        "Stripe API Key",
		Regex:       regexp.MustCompile(`(?:r|s)k_(?:test|live)_[0-9a-zA-Z]{24}`),
		Description: "Stripe Secret Key exposed",
		Risk:        "Critical",
	},
	{
		Name:        "Facebook Access Token",
		Regex:       regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
		Description: "Facebook Access Token exposed",
		Risk:        "High",
	},
	{
		Name:        "Slack Token",
		Regex:       regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`),
		Description: "Slack Token exposed",
		Risk:        "Critical",
	},
	{
		Name:        "GitHub Personal Access Token",
		Regex:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Description: "GitHub Personal Access Token exposed",
		Risk:        "Critical",
	},
	{
		Name:        "Generic API Key",
		Regex:       regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer)[ \t]*[:=][ \t]*['"][\w\-\.]{20,}['"]`),
		Description: "Potential generic API key or token exposed",
		Risk:        "High",
	},

	// --- Template Injection (SSTI) ---
	{
		Name:        "SSTI (Jinja2/Python)",
		Regex:       regexp.MustCompile(`\{\{.*?\}\}|{% ?.*? ?%}`),
		Description: "Potential Jinja2/Python Template Injection",
		Risk:        "High",
	},
	{
		Name:        "SSTI (Java)",
		Regex:       regexp.MustCompile(`\$\{.*?\}`),
		Description: "Potential Java/SSTI Injection",
		Risk:        "High",
	},

	// --- Insecure Deserialization ---
	{
		Name:        "PHP Object Injection",
		Regex:       regexp.MustCompile(`[O]:\d+:"`),
		Description: "Potential PHP Object Injection (serialized data)",
		Risk:        "Critical",
	},
	{
		Name:        "Java Serialization Header",
		Regex:       regexp.MustCompile(`\xac\xed\x00\x05`),
		Description: "Java Serialized Data Header Detected",
		Risk:        "Critical",
	},

	// --- Open Redirect ---
	{
		Name:        "Open Redirect",
		Regex:       regexp.MustCompile(`(?i)(redirect|return|url|next|continue|dest)=http`),
		Description: "Potential open redirect parameter",
		Risk:        "Medium",
	},

	// --- CSRF ---
	{
		Name:        "Missing CSRF Token (Form)",
		Regex:       regexp.MustCompile(`(?i)<form[^>]*>`),
		Description: "HTML form found (check for CSRF token manually)",
		Risk:        "Medium",
	},

	// --- HTTP Headers / CRLF ---
	{
		Name:        "CRLF Injection",
		Regex:       regexp.MustCompile(`(%0d%0a|%0a%0d|\\r\\n|\\n\\r)`),
		Description: "Potential CRLF injection (Response Splitting)",
		Risk:        "Medium",
	},

	// --- Directory Listing ---
	{
		Name:        "Directory Listing",
		Regex:       regexp.MustCompile(`(?i)(index of /|directory listing for|parent directory)`),
		Description: "Directory listing enabled",
		Risk:        "Low",
	},

	// --- LDAP Injection ---
	{
		Name:        "LDAP Injection",
		Regex:       regexp.MustCompile(`(?i)(cn=|uid=|ou=|dc=|\(\&\(objectClass=|\(\|(objectClass=)`),
		Description: "Potential LDAP Injection",
		Risk:        "High",
	},

	// --- XPath Injection ---
	{
		Name:        "XPath Injection",
		Regex:       regexp.MustCompile(`(?i)(//user\[|//password\[|' or '1'='1|' or 1=1)`),
		Description: "Potential XPath Injection",
		Risk:        "High",
	},

	// --- Client-Side Risks ---
	{
		Name:        "DOM Clobbering",
		Regex:       regexp.MustCompile(`(?i)(id=["']?window["']?|name=["']?window["']?)`),
		Description: "Potential DOM Clobbering",
		Risk:        "Medium",
	},
	{
		Name:        "Insecure Iframe",
		Regex:       regexp.MustCompile(`(?i)<iframe\s+src=["']?http:`),
		Description: "Mixed content iframe",
		Risk:        "Low",
	},

	// --- Error Messages (Information Leak) ---
	{
		Name:        "Stack Trace (Java)",
		Regex:       regexp.MustCompile(`(?i)(java\.lang\.NullPointerException|at java\.lang\.|full stack trace|Java stack trace)`),
		Description: "Java stack trace exposed",
		Risk:        "Low",
	},
	{
		Name:        "Stack Trace (PHP)",
		Regex:       regexp.MustCompile(`(?i)(Fatal error:|Parse error:|Uncaught exception|Stack trace:)`),
		Description: "PHP error/stack trace exposed",
		Risk:        "Low",
	},
	{
		Name:        "Stack Trace (Python)",
		Regex:       regexp.MustCompile(`(?i)(Traceback \(most recent call last\)|File ".*", line \d+, in)`),
		Description: "Python traceback exposed",
		Risk:        "Low",
	},
}
