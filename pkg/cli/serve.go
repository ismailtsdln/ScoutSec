package cli

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/ScoutSec/pkg/dashboard"
	"github.com/spf13/cobra"
)

var (
	dashboardPort string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the ScoutSec web dashboard",
	Run: func(cmd *cobra.Command, args []string) {
		if DB == nil {
			fmt.Println("Error: Database not initialized. Please ensure --db is provided or use default.")
			os.Exit(1)
		}

		fmt.Println("Starting Web Dashboard...")
		dash := dashboard.NewDashboard(DB)
		if err := dash.Start(dashboardPort); err != nil {
			fmt.Printf("Dashboard error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVarP(&dashboardPort, "port", "P", "9090", "Port to listen on for the dashboard")
}
