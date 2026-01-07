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

// GenerateSARIF saves the report as a SARIF file.
func (r *Report) GenerateSARIF(filename string) error {
	// ... (Existing SARIF implementation omitted for brevity in this snippet, assumes it stays same or I can preserve it)
	// Actually, I need to include the full file content if I am overwriting.
	// Let me copy the SARIF and CSV parts from my previous view.
	return r.generateSARIFImpl(filename) // Helper to keep code clean here or I just paste it all.
}

// generateSARIFImpl is the actual implementation
func (r *Report) generateSARIFImpl(filename string) error {
	rules := []Rule{}
	results := []Result{}
	ruleMap := make(map[string]bool)

	for _, issue := range r.Issues {
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
	Level     string     `json:"level"`
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

// GenerateCSV saves the report as a CSV file.
func (r *Report) GenerateCSV(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{"Name", "Severity", "URL", "Description", "Evidence"}
	if err := writer.Write(header); err != nil {
		return err
	}

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

	// --- Cover Page ---
	pdf.AddPage()

	// Add background color strip
	pdf.SetFillColor(44, 62, 80)  // Dark Blue
	pdf.Rect(0, 0, 210, 297, "F") // Full page background? No, maybe just a header strip.
	// Let's do a stylish cover.

	// Reset fill to white for content area if we want, but let's do a dark cover.
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 40)
	pdf.Ln(80)
	pdf.CellFormat(0, 15, "ScoutSec", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 20)
	pdf.CellFormat(0, 10, "Security Assessment Report", "", 1, "C", false, 0, "")

	pdf.Ln(50)
	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(0, 8, fmt.Sprintf("Target: %s", r.Target), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("Date: %s", r.ScanTime.Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("Scan Type: %s", r.ScanType), "", 1, "C", false, 0, "")

	// --- Table of Contents ---
	pdf.AddPage()
	pdf.SetFillColor(255, 255, 255)
	pdf.Rect(0, 0, 210, 297, "F") // Reset background to white

	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Arial", "B", 24)
	pdf.Cell(0, 20, "Table of Contents")
	pdf.Ln(20)

	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, "1. Executive Summary ..................................................... 3")
	pdf.Ln(10)
	pdf.Cell(0, 10, "2. Findings Summary ........................................................ 3")
	pdf.Ln(10)
	pdf.Cell(0, 10, "3. Detailed Findings .......................................................... 4")
	pdf.Ln(10)

	// --- Executive Summary ---
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(44, 62, 80)
	pdf.Cell(0, 15, "1. Executive Summary")
	pdf.Ln(15)

	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(0, 0, 0)
	pdf.MultiCell(0, 6, "This report contains the results of a security assessment performed by ScoutSec. The assessment aimed to identify vulnerabilities in the target application that could be exploited by attackers. The following sections provide a summary of the findings and detailed technical information for remediation.", "", "L", false)
	pdf.Ln(10)

	// Severity counts
	severityCounts := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
	for _, issue := range r.Issues {
		severityCounts[issue.Severity]++
	}

	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "2. Findings Summary")
	pdf.Ln(10)

	// Simple Bar Chart visualization (simulated with rectangles)
	severities := []string{"Critical", "High", "Medium", "Low", "Info"}
	colors := [][]int{{231, 76, 60}, {230, 126, 34}, {241, 196, 15}, {46, 204, 113}, {52, 152, 219}}

	maxCount := 0
	for _, c := range severityCounts {
		if c > maxCount {
			maxCount = c
		}
	}
	if maxCount == 0 {
		maxCount = 1
	} // Avoid div by zero

	width := 30.0
	pdf.SetFont("Arial", "B", 10)
	for i, sev := range severities {
		count := severityCounts[sev]
		// Label
		pdf.CellFormat(width, 10, sev, "", 0, "L", false, 0, "")

		// Bar
		barLen := float64(count) / float64(maxCount) * 100.0
		if barLen == 0 {
			barLen = 1
		} // Min width

		pdf.SetFillColor(colors[i][0], colors[i][1], colors[i][2])
		x := pdf.GetX()
		y := pdf.GetY()
		pdf.Rect(x, y+2, barLen, 6, "F")

		pdf.SetX(pdf.GetX() + 110) // Move past bar area

		// Count label
		pdf.CellFormat(20, 10, fmt.Sprintf("%d", count), "", 1, "L", false, 0, "")
	}
	pdf.Ln(10)

	// --- Detailed Findings ---
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(44, 62, 80)
	pdf.Cell(0, 15, "3. Detailed Findings")
	pdf.Ln(15)

	if len(r.Issues) == 0 {
		pdf.SetFont("Arial", "", 12)
		pdf.SetTextColor(0, 0, 0)
		pdf.Cell(0, 10, "No issues found.")
	} else {
		for i, issue := range r.Issues {
			pdf.SetFont("Arial", "B", 14)
			pdf.SetTextColor(0, 0, 0)
			pdf.Cell(0, 10, fmt.Sprintf("%d. %s", i+1, issue.Name))
			pdf.Ln(10)

			// Badge
			r, g, b := 52, 152, 219
			switch issue.Severity {
			case "Critical":
				r, g, b = 231, 76, 60
			case "High":
				r, g, b = 230, 126, 34
			case "Medium":
				r, g, b = 241, 196, 15
			case "Low":
				r, g, b = 46, 204, 113
			}
			pdf.SetFillColor(r, g, b)
			pdf.SetTextColor(255, 255, 255)
			pdf.SetFont("Arial", "B", 10)
			pdf.CellFormat(30, 8, issue.Severity, "", 1, "C", true, 0, "")

			pdf.SetTextColor(0, 0, 0)
			pdf.SetFont("Arial", "", 11)
			pdf.Ln(5)

			pdf.SetFont("Arial", "B", 11)
			pdf.Write(6, "URL: ")
			pdf.SetFont("Arial", "", 11)
			pdf.Write(6, issue.URL)
			pdf.Ln(8)

			pdf.SetFont("Arial", "B", 11)
			pdf.Write(6, "Description: ")
			pdf.SetFont("Arial", "", 11)
			pdf.MultiCell(0, 6, issue.Description, "", "L", false)
			pdf.Ln(4)

			pdf.SetFont("Arial", "B", 11)
			pdf.Write(6, "Evidence:")
			pdf.Ln(6)
			pdf.SetFont("Courier", "", 10)
			pdf.SetFillColor(240, 240, 240)
			pdf.MultiCell(0, 5, issue.Evidence, "0", "L", true)

			pdf.Ln(10)

			// Line separator
			pdf.SetDrawColor(200, 200, 200)
			pdf.Line(10, pdf.GetY(), 200, pdf.GetY())
			pdf.Ln(10)
		}
	}

	// Add footer logic for pages
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 10, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	return pdf.OutputFileAndClose(filename)
}

// CodeBlock helper helper.
// Actually gofpdf doesn't have CodeBlock, just doing inline func above was pseudo.
// I can just execute the commands. But since I used it inside the loop,
// I need those commands to be direct.
