package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionString = "1.0.0"

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display ScoutSec version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ScoutSec v%s\n", versionString)
		fmt.Println("Enterprise-grade DAST Platform")
		fmt.Println("https://github.com/ismailtsdln/ScoutSec")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
