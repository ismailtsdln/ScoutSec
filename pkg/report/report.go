package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/jung-kurt/gofpdf"
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

// --- SARIF Definitions ---

type SarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name            string `json:"name"`
	InformationURI  string `json:"informationUri"`
	SemanticVersion string `json:"semanticVersion"`
	Rules           []Rule `json:"rules"`
}

type Rule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription ShortDescription `json:"shortDescription"`
	HelpUri          string           `json:"helpUri,omitempty"`
}

type ShortDescription struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"` // error, warning, note
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

// GenerateSARIF saves the report as a SARIF file.
func (r *Report) GenerateSARIF(filename string) error {
	rules := []Rule{}
	results := []Result{}
	ruleMap := make(map[string]bool)

	for _, issue := range r.Issues {
		// Dedup rules
		if !ruleMap[issue.Name] {
			ruleMap[issue.Name] = true
			rules = append(rules, Rule{
				ID:   issue.Name,
				Name: issue.Name,
				ShortDescription: ShortDescription{
					Text: issue.Description,
				},
				HelpUri: "https://github.com/ismailtsdln/ScoutSec",
			})
		}

		// Map Severity to SARIF Level
		level := "note"
		switch issue.Severity {
		case "Critical", "High":
			level = "error"
		case "Medium":
			level = "warning"
		case "Low", "Info":
			level = "note"
		}

		results = append(results, Result{
			RuleID: issue.Name,
			Level:  level,
			Message: Message{
				Text: issue.Description + "\n\nEvidence: " + issue.Evidence,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: issue.URL,
						},
					},
				},
			},
		})
	}

	sarif := SarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:            "ScoutSec",
						InformationURI:  "https://github.com/ismailtsdln/ScoutSec",
						SemanticVersion: "1.0.0",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// GenerateCSV saves the report as a CSV file.
func (r *Report) GenerateCSV(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	// Write Header
	header := []string{"Name", "Severity", "URL", "Description", "Evidence"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write Rows
	for _, issue := range r.Issues {
		row := []string{
			issue.Name,
			issue.Severity,
			issue.URL,
			issue.Description,
			issue.Evidence,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// GeneratePDF generates a professional PDF executive report.
func (r *Report) GeneratePDF(filename string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("ScoutSec Security Report", false)
	pdf.SetAuthor("ScoutSec", false)

	pdf.AddPage()

	// Header
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(44, 62, 80) // Dark blue
	pdf.CellFormat(0, 15, "ScoutSec Security Report", "", 1, "C", false, 0, "")
	pdf.Ln(5)

	// Target info
	pdf.SetFont("Arial", "", 12)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, fmt.Sprintf("Target: %s", r.Target), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("Scan Time: %s", r.ScanTime.Format(time.RFC1123)), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("Scan Type: %s", r.ScanType), "", 1, "L", false, 0, "")
	pdf.Ln(10)

	// Executive Summary
	pdf.SetFont("Arial", "B", 16)
	pdf.CellFormat(0, 10, "Executive Summary", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 11)

	// Count severities
	severityCounts := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
	for _, issue := range r.Issues {
		severityCounts[issue.Severity]++
	}

	pdf.CellFormat(0, 7, fmt.Sprintf("Total Findings: %d", len(r.Issues)), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 7, fmt.Sprintf("Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d",
		severityCounts["Critical"], severityCounts["High"], severityCounts["Medium"],
		severityCounts["Low"], severityCounts["Info"]), "", 1, "L", false, 0, "")
	pdf.Ln(10)

	// Findings Table
	pdf.SetFont("Arial", "B", 14)
	pdf.CellFormat(0, 10, "Detailed Findings", "", 1, "L", false, 0, "")

	// Table Header
	pdf.SetFont("Arial", "B", 10)
	pdf.SetFillColor(44, 62, 80)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(60, 8, "Name", "1", 0, "C", true, 0, "")
	pdf.CellFormat(25, 8, "Severity", "1", 0, "C", true, 0, "")
	pdf.CellFormat(95, 8, "URL", "1", 1, "C", true, 0, "")

	// Table Rows
	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(0, 0, 0)
	for _, issue := range r.Issues {
		// Severity color
		switch issue.Severity {
		case "Critical":
			pdf.SetFillColor(231, 76, 60)
		case "High":
			pdf.SetFillColor(230, 126, 34)
		case "Medium":
			pdf.SetFillColor(241, 196, 15)
		case "Low":
			pdf.SetFillColor(46, 204, 113)
		default:
			pdf.SetFillColor(52, 152, 219)
		}

		// Truncate long strings
		name := issue.Name
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		urlStr := issue.URL
		if len(urlStr) > 50 {
			urlStr = urlStr[:47] + "..."
		}

		pdf.CellFormat(60, 7, name, "1", 0, "L", false, 0, "")
		pdf.CellFormat(25, 7, issue.Severity, "1", 0, "C", true, 0, "")
		pdf.CellFormat(95, 7, urlStr, "1", 1, "L", false, 0, "")
	}

	pdf.Ln(10)

	// Footer
	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 5, "Generated by ScoutSec - https://github.com/ismailtsdln/ScoutSec", "", 1, "C", false, 0, "")

	return pdf.OutputFileAndClose(filename)
}
