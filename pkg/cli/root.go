package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ismailtsdln/ScoutSec/pkg/database"
	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

var (
	cfgFile string
	dbFile  string
	DB      *database.DB
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scoutsec",
	Short: "ScoutSec is a modern web application security scanning toolkit",
	Long: `ScoutSec combines passive passive proxy-based analysis with active fuzzing
capabilities to detect security vulnerabilities in web applications.

It is designed to be a standalone tool that integrates with your CI/CD pipeline
and provides comprehensive reporting.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if dbFile != "" {
			var err error
			DB, err = database.Init(dbFile)
			if err != nil {
				fmt.Printf("Warning: Failed to initialize database: %v\n", err)
			} else {
				fmt.Println("Database initialized successfully.")
				// Hook up report callback
				report.IssueCallback = func(issue report.Issue) {
					finding := &database.Finding{
						CreatedAt:   time.Now(),
						Target:      report.GlobalReport.Target,
						Name:        issue.Name,
						Description: issue.Description,
						Severity:    issue.Severity,
						URL:         issue.URL,
						Evidence:    issue.Evidence,
					}
					if err := DB.SaveFinding(finding); err != nil {
						fmt.Printf("Error saving finding to DB: %v\n", err)
					}
				}
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.scoutsec.yaml)")
	rootCmd.PersistentFlags().StringVar(&dbFile, "db", "scoutsec.db", "database file path")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".scoutsec" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".scoutsec")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
