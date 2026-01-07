# ScoutSec

**ScoutSec** — Modern Web Application Security Scanning Toolkit  
A unified passive and active scanning solution with advanced analysis, CI/CD integration, and comprehensive reporting.


---

## 🚀 Features

- **Passive Scanning**: Proxy-based traffic analysis to detect vulnerabilities without sending malicious payloads.
- **Active Scanning**: Targeted security fuzzing and payload injection (under specific flags).
- **Advanced Analysis**: OWASP Top 10 detection patterns, custom payload support.
- **Reporting**: Automated generating of structured JSON and detailed HTML reports.
- **Integration**: Designed for CI/CD pipelines and easy integration with other tools (Burp/ZAP).

---

## 🛠️ Installation

```bash
go install github.com/ismailtsdln/ScoutSec/cmd/scoutsec@latest
```

## 📌 Usage

### Scanning

To perform a scan against a target:

```bash
scoutsec scan https://target.com --active --passive
```

### Reporting

To generate a report from findings:

```bash
scoutsec report --format html
```

## 🧪 Development

### Prerequisites

- Go 1.21+

### Running Tests

```bash
go test ./...
```

### Project Structure

- `cmd/`: Entry points.
- `pkg/cli/`: CLI command definitions.
- `pkg/scanner/`: Core scanning logic (active/passive).
- `pkg/analysis/`: Detection and analysis engines.
- `pkg/report/`: Reporting modules.

---

## 📜 License

Licensed under Apache-2.0.
