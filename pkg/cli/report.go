package cli

import (
	"fmt"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
	"github.com/spf13/cobra"
)

var reportFormat string

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report from previous scans",
	Long: `Generate a report from the findings of previous scans.
Supported formats include HTML and JSON.`,
	Run: func(cmd *cobra.Command, args []string) {
		reportFile := "report." + reportFormat
		if len(args) > 0 {
			reportFile = args[0]
		}

		fmt.Printf("Generating report in %s format to %s\n", reportFormat, reportFile)

		// Load results (mock for now, or assume previously scanned)
		// In a real scenario, we'd load from a DB or temp file
		r := &report.Report{
			Target:   "scanned-target",
			ScanTime: time.Now(),
			Issues:   []report.Issue{}, // TODO: Load actual issues
			ScanType: "Mixed",
		}

		var err error
		switch reportFormat {
		case "json":
			err = r.GenerateJSON(reportFile)
		case "html":
			err = r.GenerateHTML(reportFile)
		case "sarif":
			err = r.GenerateSARIF(reportFile)
		default:
			fmt.Printf("Unknown format: %s\n", reportFormat)
			return
		}

		if err != nil {
			fmt.Printf("Error generating report: %v\n", err)
		} else {
			fmt.Println("Report generated successfully.")
		}
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)

	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "html", "Report format (html, json, sarif)")
}
