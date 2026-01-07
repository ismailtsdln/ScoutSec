# ScoutSec

**ScoutSec** — Modern Web Application Security Scanning Toolkit  
A unified passive and active scanning solution with advanced analysis, CI/CD integration, and comprehensive reporting.

## 🚀 Features

### Core Scanning
- **Passive Scanning**: Proxy-based traffic analysis to detect vulnerabilities without sending malicious payloads.
- **Active Scanning**: Targeted security fuzzing and payload injection with concurrent worker pools.
- **Advanced Analysis**: OWASP Top 10 detection patterns with custom payload support.

### Modern Web & SPA
- **Headless Browser**: JavaScript execution via `chromedp` for DOM-based vulnerability detection.
- **Screenshot Capture**: Automated evidence collection for visual confirmation.
- **SPA Crawling**: JavaScript-aware link discovery for Single Page Applications.

### API Security
- **OpenAPI/Swagger**: Parse and automatically test REST API endpoints from spec files.
- **GraphQL Security**: Introspection detection, batch query DOS, and recursive query vulnerability testing.
- **API Fuzzing**: BOLA/IDOR checks, JSON/XML injection detection.

### Authentication & Sessions
- **JWT Analysis**: Algorithm detection, claims inspection, security validation.
- **Form Authentication**: Automated browser-based login.
- **Session Management**: Cookie jar with persistent header injection.

### Reconnaissance
- **Subdomain Enumeration**: Passive (Certificate Transparency) and active (bruteforce) discovery.
- **Tech Fingerprinting**: Detect frameworks, CMS, libraries, and server technologies.

### Reporting
- **Multiple Formats**: Automated JSON and HTML report generation.
- **Severity Classification**: Risk-based categorization of findings.
- **CI/CD Ready**: Designed for seamless pipeline integration.

---

## 🛠️ Installation

```bash
go install github.com/ismailtsdln/ScoutSec/cmd/scoutsec@latest
```

## 📌 Usage

### Web Application Scanning

```bash
# Active fuzzing
scoutsec scan https://target.com --active

# Passive proxy mode
scoutsec scan https://target.com --passive

# Browser-based scanning with screenshot
scoutsec scan https://target.com --browser

# SPA crawling
scoutsec scan https://target.com --crawl

# Combined mode
scoutsec scan https://target.com --active --browser --crawl
```

### API Security Testing

```bash
# Scan REST API with OpenAPI spec
scoutsec api --spec openapi.yaml --base-url https://api.example.com

# Scan GraphQL endpoint
scoutsec api --graphql https://api.example.com/graphql
```

### Authentication Testing

```bash
# Analyze JWT token
scoutsec auth --jwt "eyJhbGc..."
```

### Reconnaissance

```bash
# Passive subdomain enumeration
scoutsec recon --domain example.com --passive

# Active subdomain bruteforce
scoutsec recon --domain example.com --active

# Technology fingerprinting
scoutsec recon --domain example.com --fingerprint

# Combined reconnaissance
scoutsec recon --domain example.com --passive --fingerprint
```

### Reporting

```bash
scoutsec report --format html
```

## 🧪 Development

### Prerequisites

- Go 1.21+
- Chrome/Chromium (for headless browser features)

### Running Tests

```bash
go test ./...
```

### Project Structure

- `cmd/`: Entry points.
- `pkg/cli/`: CLI command definitions.
- `pkg/scanner/`: Core scanning logic (active/passive/browser).
- `pkg/api/`: API security testing (OpenAPI/GraphQL).
- `pkg/analysis/`: Detection and analysis engines.
- `pkg/report/`: Reporting modules.

---

## 📜 License

Licensed under Apache-2.0.
