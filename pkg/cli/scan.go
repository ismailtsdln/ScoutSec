package cli

import (
	"fmt"

	"github.com/ismailtsdln/ScoutSec/pkg/scanner/active"
	"github.com/ismailtsdln/ScoutSec/pkg/scanner/passive"
	"github.com/spf13/cobra"
)

var (
	activeScan  bool
	passiveScan bool
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Perform a security scan against a target",
	Long: `Perform a security scan against a target URL.
You can choose to run active scanning, passive scanning (proxy), or both.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		fmt.Printf("Starting scan against %s\n", target)
		if activeScan {
			fmt.Println("Active scanning enabled")
			fuzzer := active.NewFuzzer(target, 5) // 5 concurrent workers
			fuzzer.Start()
		}
		if passiveScan {
			fmt.Println("Passive scanning enabled on :8080")
			scanner := passive.NewProxyScanner(":8080")
			go func() {
				if err := scanner.Start(); err != nil {
					fmt.Printf("Error starting proxy: %v\n", err)
				}
			}()
			// Block or wait signal? For now we just block to let proxy run.
			select {}
		}

		if !activeScan && !passiveScan {
			fmt.Println("Warning: No scan mode selected. Use --active or --passive (or both).")
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().BoolVarP(&activeScan, "active", "a", false, "Enable active scanning (fuzzing)")
	scanCmd.Flags().BoolVarP(&passiveScan, "passive", "p", false, "Enable passive scanning (proxy mode)")
}
