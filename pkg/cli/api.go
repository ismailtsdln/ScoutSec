package cli

import (
	"fmt"

	"github.com/ismailtsdln/ScoutSec/pkg/api"
	"github.com/ismailtsdln/ScoutSec/pkg/report"
	"github.com/spf13/cobra"
)

var (
	apiSpecFile     string
	apiBaseURL      string
	graphqlEndpoint string
)

// apiCmd represents the api command
var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Scan APIs using OpenAPI/Swagger specifications or GraphQL",
	Long: `Scan API endpoints defined in OpenAPI/Swagger specs or GraphQL endpoints.
Automatically tests for BOLA/IDOR, JSON injection, GraphQL introspection, and other API-specific vulnerabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		// GraphQL scanning mode
		if graphqlEndpoint != "" {
			fmt.Printf("Scanning GraphQL endpoint: %s\n", graphqlEndpoint)
			report.InitReport(graphqlEndpoint, "GraphQL")

			fuzzer := api.NewGraphQLFuzzer(graphqlEndpoint)
			fuzzer.IntrospectionQuery()
			fuzzer.FuzzQueries()

			if err := report.GlobalReport.GenerateJSON("graphql_report.json"); err != nil {
				fmt.Printf("Error generating report: %v\n", err)
			} else {
				fmt.Println("GraphQL scan report saved to graphql_report.json")
			}
			return
		}

		// OpenAPI scanning mode
		if apiSpecFile == "" {
			fmt.Println("Error: --spec flag is required (or use --graphql for GraphQL scanning)")
			return
		}

		if apiBaseURL == "" {
			fmt.Println("Error: --base-url flag is required")
			return
		}

		fmt.Printf("Loading OpenAPI spec from: %s\n", apiSpecFile)
		scanner, err := api.LoadFromFile(apiSpecFile)
		if err != nil {
			fmt.Printf("Error loading API spec: %v\n", err)
			return
		}

		endpoints := scanner.ExtractEndpoints()
		fmt.Printf("Discovered %d API endpoints\n", len(endpoints))

		report.InitReport(apiBaseURL, "API")

		fuzzer := api.NewAPIFuzzer(apiBaseURL)
		for _, endpoint := range endpoints {
			fuzzer.FuzzEndpoint(endpoint)
		}

		// Save report
		if err := report.GlobalReport.GenerateJSON("api_report.json"); err != nil {
			fmt.Printf("Error generating report: %v\n", err)
		} else {
			fmt.Println("API scan report saved to api_report.json")
		}
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)

	apiCmd.Flags().StringVar(&apiSpecFile, "spec", "", "Path to OpenAPI/Swagger spec file")
	apiCmd.Flags().StringVar(&apiBaseURL, "base-url", "", "Base URL of the API to test")
	apiCmd.Flags().StringVar(&graphqlEndpoint, "graphql", "", "GraphQL endpoint to test (alternative to --spec)")
}
