package report

import (
	"encoding/json"
	"os"
	"text/template"
	"time"
)

// Issue represents a security finding.
type Issue struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // High, Medium, Low
	URL         string `json:"url"`
	Evidence    string `json:"evidence"`
}

// Report represents the final scan report.
type Report struct {
	Target   string    `json:"target"`
	ScanTime time.Time `json:"scan_time"`
	Issues   []Issue   `json:"issues"`
	ScanType string    `json:"scan_type"` // Active, Passive, Mixed
}

// GenerateJSON saves the report as a JSON file.
func (r *Report) GenerateJSON(filename string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// GenerateHTML saves the report as an HTML file.
func (r *Report) GenerateHTML(filename string) error {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
	<title>ScoutSec Report - {{.Target}}</title>
	<style>
		body { font-family: sans-serif; margin: 20px; }
		h1 { color: #2c3e50; }
		.issue { border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }
		.High { border-left: 5px solid #e74c3c; }
		.Medium { border-left: 5px solid #f39c12; }
		.Low { border-left: 5px solid #3498db; }
		.meta { color: #7f8c8d; font-size: 0.9em; }
	</style>
</head>
<body>
	<h1>ScoutSec Scan Report</h1>
	<p class="meta">Target: {{.Target}} | Time: {{.ScanTime}} | Type: {{.ScanType}}</p>
	
	<h2>Findings</h2>
	{{if not .Issues}}
		<p>No issues found.</p>
	{{else}}
		{{range .Issues}}
			<div class="issue {{.Severity}}">
				<h3>{{.Name}} <span style="font-size:0.6em; color: gray;">({{.Severity}})</span></h3>
				<p><strong>URL:</strong> {{.URL}}</p>
				<p>{{.Description}}</p>
				<p><strong>Evidence:</strong> <pre>{{.Evidence}}</pre></p>
			</div>
		{{end}}
	{{end}}
</body>
</html>
`
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, r)
}
