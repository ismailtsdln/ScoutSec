package cli

import (
	"fmt"

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
		fmt.Printf("Generating report in %s format\n", reportFormat)
		// TODO: Implement reporting logic
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)

	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "html", "Report format (html, json)")
}
