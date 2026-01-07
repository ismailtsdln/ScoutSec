package cli

import (
	"fmt"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
	"github.com/ismailtsdln/ScoutSec/pkg/scanner/active"
	"github.com/ismailtsdln/ScoutSec/pkg/scanner/browser"
	"github.com/ismailtsdln/ScoutSec/pkg/scanner/passive"
	"github.com/spf13/cobra"
)

var (
	activeScan  bool
	passiveScan bool
	useBrowser  bool
	crawl       bool
	resume      bool
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Perform a security scan against a target",
	Long: `Perform a security scan against a target URL.
You can choose to run active scanning, passive scanning (proxy), headless browser scan, crawling, or a combination.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		fmt.Printf("Starting scan against %s\n", target)

		scanType := "Mixed"
		// Logic to determine type string...

		report.InitReport(target, scanType)

		if useBrowser || crawl {
			fmt.Println("Browser engine initialized")
			bScanner := browser.NewScanner(30 * time.Second)

			if useBrowser {
				fmt.Println("Taking screenshot...")
				if err := bScanner.CaptureScreenshot(target, "screenshot.png"); err != nil {
					fmt.Printf("Error capturing screenshot: %v\n", err)
				}
			}

			if crawl {
				if resume && DB != nil && DB.IsScanned(target, "crawl_phase") {
					fmt.Println("Resuming: Skipping crawl phase (already done)")
				} else {
					fmt.Println("Crawling target (SPA mode)...")
					links, err := bScanner.Crawl(target)
					if err != nil {
						fmt.Printf("Error crawling: %v\n", err)
					} else {
						fmt.Printf("Found %d links:\n", len(links))
						for _, l := range links {
							fmt.Println(" - " + l)
							// Add to report as info
							report.AddIssue(report.Issue{
								Name:        "Discovered Link",
								Description: "Link found via SPA Crawl",
								Severity:    "Info",
								URL:         target,
								Evidence:    l,
							})
						}
						// Mark done
						if DB != nil {
							DB.MarkScanned(target, "crawl_phase")
						}
					}
				}
			}
		}

		if activeScan {
			if resume && DB != nil && DB.IsScanned(target, "active_phase") {
				fmt.Println("Resuming: Skipping active scan phase (already done)")
			} else {
				fmt.Println("Active scanning enabled")
				fuzzer := active.NewFuzzer(target, 5)
				fuzzer.Start()
				// Mark done
				if DB != nil {
					DB.MarkScanned(target, "active_phase")
				}
			}
		}
		if passiveScan {
			fmt.Println("Passive scanning enabled on :8080")
			scanner := passive.NewProxyScanner(":8080")
			go func() {
				if err := scanner.Start(); err != nil {
					fmt.Printf("Error starting proxy: %v\n", err)
				}
			}()
			select {} // Block for passive
		}

		// If only active/browser scan, save report
		if (activeScan || useBrowser || crawl) && !passiveScan {
			if err := report.GlobalReport.GenerateJSON("scoutsec_report.json"); err != nil {
				fmt.Printf("Error generating report: %v\n", err)
			} else {
				fmt.Println("Report saved to scoutsec_report.json")
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().BoolVarP(&activeScan, "active", "a", false, "Enable active scanning (fuzzing)")
	scanCmd.Flags().BoolVarP(&passiveScan, "passive", "p", false, "Enable passive scanning (proxy mode)")
	scanCmd.Flags().BoolVarP(&useBrowser, "browser", "b", false, "Enable headless browser scanning (Screenshots & DOM)")
	scanCmd.Flags().BoolVarP(&crawl, "crawl", "c", false, "Enable SPA crawling to find links")
	scanCmd.Flags().BoolVar(&resume, "resume", false, "Resume scan (skip already processed steps)")
}
