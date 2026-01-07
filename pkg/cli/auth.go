package cli

import (
	"fmt"

	"github.com/ismailtsdln/ScoutSec/pkg/auth"
	"github.com/spf13/cobra"
)

var (
	jwtToken string
)

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Test authentication mechanisms",
	Long:  `Analyze authentication mechanisms including JWT tokens, form-based login, and session management.`,
	Run: func(cmd *cobra.Command, args []string) {
		if jwtToken != "" {
			fmt.Println("Analyzing JWT token...")
			analyzer := auth.NewJWTAnalyzer()
			if err := analyzer.AnalyzeToken(jwtToken); err != nil {
				fmt.Printf("Error analyzing JWT: %v\n", err)
				return
			}

			// Decode and display payload
			payload, err := analyzer.DecodePayload(jwtToken)
			if err != nil {
				fmt.Printf("Error decoding payload: %v\n", err)
			} else {
				fmt.Println("\n[JWT] Decoded Payload:")
				for key, value := range payload {
					fmt.Printf("  %s: %v\n", key, value)
				}
			}
		} else {
			fmt.Println("Error: No authentication method specified.")
			fmt.Println("Use --jwt <token> to analyze a JWT token")
		}
	},
}

func init() {
	rootCmd.AddCommand(authCmd)

	authCmd.Flags().StringVar(&jwtToken, "jwt", "", "JWT token to analyze")
}
