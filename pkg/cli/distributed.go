package cli

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/ScoutSec/pkg/distributed"
	"github.com/ismailtsdln/ScoutSec/pkg/report"
	"github.com/spf13/cobra"
)

var (
	masterPort string
	masterURL  string
)

var distributedCmd = &cobra.Command{
	Use:   "distributed",
	Short: "Distributed scanning commands",
}

var masterCmd = &cobra.Command{
	Use:   "master",
	Short: "Start the distributed master node",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting Master Node...")
		report.InitReport("Distributed Master", "Distributed")
		m := distributed.NewMaster(masterPort)

		// Example: Add a dummy task for testing
		m.AddTask("http://testphp.vulnweb.com")

		if err := m.Start(); err != nil {
			fmt.Printf("Master error: %v\n", err)
			os.Exit(1)
		}
	},
}

var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Start a distributed worker node",
	Run: func(cmd *cobra.Command, args []string) {
		if masterURL == "" {
			fmt.Println("Error: --master-url required")
			os.Exit(1)
		}
		fmt.Println("Starting Worker Node...")
		w := distributed.NewWorker(masterURL)
		w.Start()
	},
}

func init() {
	rootCmd.AddCommand(distributedCmd)
	distributedCmd.AddCommand(masterCmd)
	distributedCmd.AddCommand(workerCmd)

	masterCmd.Flags().StringVar(&masterPort, "port", "8090", "Port to listen on")
	workerCmd.Flags().StringVar(&masterURL, "master-url", "http://localhost:8090", "URL of the master node")
}
