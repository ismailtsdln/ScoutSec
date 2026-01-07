package cli

import (
	"fmt"

	"github.com/ismailtsdln/ScoutSec/pkg/recon"
	"github.com/spf13/cobra"
)

var (
	reconDomain        string
	passiveEnum        bool
	activeEnum         bool
	fingerprintEnabled bool
)

// reconCmd represents the recon command
var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Reconnaissance and asset discovery",
	Long:  `Perform reconnaissance including subdomain enumeration and technology fingerprinting.`,
	Run: func(cmd *cobra.Command, args []string) {
		if reconDomain == "" {
			fmt.Println("Error: --domain flag is required")
			return
		}

		// Subdomain enumeration
		if passiveEnum || activeEnum {
			fmt.Printf("\n[*] Starting subdomain enumeration for: %s\n", reconDomain)
			enumerator := recon.NewSubdomainEnumerator()

			if passiveEnum {
				fmt.Println("\n[*] Passive subdomain enumeration (Certificate Transparency)...")
				subdomains, err := enumerator.EnumeratePassive(reconDomain)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Printf("\n[+] Found %d subdomains:\n", len(subdomains))
					for _, sub := range subdomains {
						fmt.Printf("  - %s\n", sub)
					}
				}
			}

			if activeEnum {
				fmt.Println("\n[*] Active subdomain enumeration (Bruteforce)...")
				wordlist := recon.GetCommonWordlist()
				found := enumerator.EnumerateActive(reconDomain, wordlist)
				fmt.Printf("\n[+] Found %d active subdomains\n", len(found))
			}
		}

		// Technology fingerprinting
		if fingerprintEnabled {
			target := fmt.Sprintf("https://%s", reconDomain)
			fmt.Printf("\n[*] Fingerprinting technologies for: %s\n", target)

			fingerprinter := recon.NewTechFingerprinter()
			techs, err := fingerprinter.Fingerprint(target)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}

			recon.PrintTechnologies(techs)
		}

		if !passiveEnum && !activeEnum && !fingerprintEnabled {
			fmt.Println("Error: No recon mode selected. Use --passive, --active, or --fingerprint")
		}
	},
}

func init() {
	rootCmd.AddCommand(reconCmd)

	reconCmd.Flags().StringVar(&reconDomain, "domain", "", "Target domain for reconnaissance (required)")
	reconCmd.Flags().BoolVar(&passiveEnum, "passive", false, "Passive subdomain enumeration")
	reconCmd.Flags().BoolVar(&activeEnum, "active", false, "Active subdomain bruteforcing")
	reconCmd.Flags().BoolVar(&fingerprintEnabled, "fingerprint", false, "Technology fingerprinting")
}
