# ScoutSec

<div align="center">

  <h1>🛡️ ScoutSec</h1>
  <p><strong>Modern Web Application Security Scanning Toolkit</strong></p>
  
  [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
  [![Go Version](https://img.shields.io/github/go-mod/go-version/ismailtsdln/ScoutSec)](go.mod)
  [![Build Status](https://github.com/ismailtsdln/ScoutSec/actions/workflows/ci.yaml/badge.svg)](https://github.com/ismailtsdln/ScoutSec/actions)

  <br>

  <p>
    <b>ScoutSec</b> is a unified, high-performance security scanner designed for modern web applications, APIs, and cloud-native environments. It bridges the gap between passive reconnaissance and active exploitation with a modular, extensible architecture.
  </p>

</div>

---

## 🚀 Features

### 🔍 Core Scanning Engine
*   **Passive Analysis**: Non-intrusive traffic analysis to detect information leaks, misconfigurations, and sensitive data exposure without sending malicious payloads.
*   **Active Fuzzing**: targeted payload injection using concurrent worker pools to identify SQLi, XSS, SSRF, and more.
*   **Advanced Detection**: Comprehensive pattern matching engine with support for custom signatures and hundreds of built-in payloads.

### 🌐 Modern Web & SPA Support
*   **Headless Browser Integration**: Uses `chromedp` to render and interact with JavaScript-heavy applications (SPAs).
*   **DOM Analysis**: Detects DOM-based XSS and client-side vulnerabilities that static analysis misses.
*   **Visual Evidence**: Automated screenshot capture for verified findings.

### 🔌 API Security
*   **OpenAPI/Swagger Scanning**: Automatically parses `openapi.yaml` or `swagger.json` specs to generate test cases for every endpoint.
*   **GraphQL Support**: comprehensive testing for Introspection, Batching attacks, and Recursive DoS.
*   **BOLA/IDOR Detection**: Automated testing for Broken Object Level Authorization vulnerabilities.

### 🔐 Authentication & Sessions
*   **JWT Security**: Deep analysis of JSON Web Tokens for weak signatures, `none` algorithm, and sensitive claim exposure.
*   **Form Authentication**: Scriptable login flows to scan behind authenticated areas.
*   **Smart Session Handling**: Persistent cookie jars and header management across all scan modules.

### 🕵️ Reconnaissance
*   **Subdomain Enumeration**: Hybrid approach using certificate transparency logs (passive) and DNS bruteforcing (active).
*   **Tech Fingerprinting**: Identifies server technologies, frameworks, and libraries to tailor attack vectors.

---

## 🛠️ Installation

### Using Go Install (Recommended)

```bash
go install github.com/ismailtsdln/ScoutSec/cmd/scoutsec@latest
```

### Building from Source

```bash
git clone https://github.com/ismailtsdln/ScoutSec.git
cd ScoutSec
go build -o scoutsec ./cmd/scoutsec
```

> **Prerequisites**:
> - Go 1.21 or higher
> - Chrome/Chromium (installed for headless browser features)

---

## 📌 Usage

ScoutSec is CLI-first and designed for easy integration into scripts and pipelines.

### 1. Web Application Scanning

**Basic Scan:**
```bash
scoutsec scan https://example.com
```

**Full Active Scan with Fuzzing:**
```bash
scoutsec scan https://example.com --active
```

**Headless Browser Scan (SPAs):**
```bash
scoutsec scan https://example.com --browser --screenshot
```

### 2. API Security Testing

**Scan REST API via OpenAPI Spec:**
```bash
scoutsec api --spec ./openapi.yaml --base-url https://api.example.com
```

**Scan GraphQL Endpoint:**
```bash
scoutsec api --graphql https://api.example.com/graphql
```

### 3. Authentication & Tokens

**Analyze a JWT:**
```bash
scoutsec auth --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Scan Authenticated Routes (Login):**
```bash
scoutsec scan https://admin.example.com \
  --login-url https://admin.example.com/login \
  --username admin \
  --password secret
```

### 4. Reconnaissance

**Enumerate Subdomains:**
```bash
scoutsec recon --domain example.com --passive --active
```

**Tech Fingerprinting:**
```bash
scoutsec recon --domain example.com --fingerprint
```

### 5. Reporting

Generate reports in different formats:

```bash
# JSON Report (Default)
scoutsec report --format json --output report.json

# HTML Report
scoutsec report --format html --output report.html
```

---

## ⚙️ Configuration

ScoutSec can be configured via YAML file or environment variables.

**Example `config.yaml`:**
```yaml
scanner:
  concurrency: 20
  timeout: 10s
  user_agent: "ScoutSec-Scanner/1.0"

active:
  payloads_file: "custom_payloads.txt"
  
reporting:
  include_sensitive: false
```

Load config:
```bash
scoutsec scan https://example.com --config ./config.yaml
```

---

## 🧪 Development

### Running Tests
```bash
go test ./... -v
```

### Project Structure
- `cmd/`: Application entry points.
- `pkg/analysis/`: Detection logic and pattern definitions.
- `pkg/scanner/`: Active and passive scanning engines.
- `pkg/api/`: API-specific testing modules.
- `pkg/recon/`: Subdomain and asset discovery.
- `pkg/report/`: Reporting and output generation.

---

## 📜 License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built with ❤️ by the ScoutSec Team</sub>
</div>
