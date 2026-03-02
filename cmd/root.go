package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version, BuildDate, and Commit are set via ldflags at build time.
var (
	Version   = "dev"
	BuildDate = "unknown"
	Commit    = "unknown"
)

// quiet suppresses all stderr progress and summary output when true.
var quiet bool

var rootCmd = &cobra.Command{
	Use:   "matlock",
	Short: "Multi-cloud security and cost investigator",
	Long: `matlock investigates your cloud infrastructure for IAM over-privilege,
cost anomalies, orphaned resources, and storage misconfigurations.

Supported providers: aws, gcp, azure`,
	SilenceUsage: true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress and summary output to stderr")
	rootCmd.AddCommand(iamCmd)
	rootCmd.AddCommand(costCmd)
	rootCmd.AddCommand(orphansCmd)
	rootCmd.AddCommand(storageCmd)
}
