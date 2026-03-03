package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/stxkxs/matlock/internal/investigate"
	"github.com/stxkxs/matlock/internal/investigate/modules"
	"github.com/stxkxs/matlock/internal/output"
)

var probeCmd = &cobra.Command{
	Use:   "probe <target>",
	Short: "Reconnaissance and security analysis of domains and IPs",
	Long: `probe runs passive reconnaissance modules against a domain or IP address.

Modules are auto-selected based on target type (domain vs IP), or can be
specified explicitly with --modules. Third-party API modules (shodan,
virustotal, sectrails) require API keys set via environment variables.

Examples:
  matlock probe example.com
  matlock probe example.com --modules dns,ssl,http
  matlock probe 8.8.8.8
  matlock probe example.com --score
  matlock probe --batch targets.txt
  matlock probe --list-modules`,
	RunE: runProbe,
}

var (
	probeModules     string
	probeExclude     string
	probeListModules bool
	probeScore       bool
	probeBatch       string
	probeParallel    int
	probeConcurrency int
	probeTimeout     time.Duration
	probeOutputFmt   string
	probeOutputFile  string
)

func init() {
	probeCmd.Flags().StringVar(&probeModules, "modules", "", "comma-separated module list (default: auto by target type)")
	probeCmd.Flags().StringVar(&probeExclude, "exclude", "", "comma-separated modules to skip")
	probeCmd.Flags().BoolVar(&probeListModules, "list-modules", false, "list all available modules with descriptions")
	probeCmd.Flags().BoolVar(&probeScore, "score", false, "run security scoring after scan")
	probeCmd.Flags().StringVar(&probeBatch, "batch", "", "file with targets (one per line, # comments allowed)")
	probeCmd.Flags().IntVar(&probeParallel, "parallel", 4, "batch worker count")
	probeCmd.Flags().IntVar(&probeConcurrency, "concurrency", 5, "per-target module concurrency")
	probeCmd.Flags().DurationVar(&probeTimeout, "timeout", 10*time.Second, "per-module timeout")
	probeCmd.Flags().StringVar(&probeOutputFmt, "output", "table", "output format: table, json")
	probeCmd.Flags().StringVar(&probeOutputFile, "output-file", "", "write output to file")
}

func runProbe(_ *cobra.Command, args []string) error {
	runner := investigate.NewRunner(modules.All())

	// --list-modules
	if probeListModules {
		return listModules(runner)
	}

	// Parse common options.
	var mods, excludes []string
	if probeModules != "" {
		mods = strings.Split(probeModules, ",")
	}
	if probeExclude != "" {
		excludes = strings.Split(probeExclude, ",")
	}

	opts := investigate.RunOptions{
		Modules:     mods,
		Exclude:     excludes,
		Concurrency: probeConcurrency,
		Timeout:     probeTimeout,
		Score:       probeScore,
	}

	// Set up output destination.
	w := os.Stdout
	if probeOutputFile != "" {
		f, err := os.Create(probeOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	ctx := context.Background()

	// --batch mode
	if probeBatch != "" {
		return runBatchProbe(ctx, runner, opts, w)
	}

	// Single target mode.
	if len(args) == 0 {
		return fmt.Errorf("target required (domain or IP address)")
	}

	target, tt, err := investigate.ValidateTarget(args[0])
	if err != nil {
		return err
	}

	if !quiet {
		opts.Progress = func(done, total int) {
			fmt.Fprintf(os.Stderr, "\rprobing %s: %d/%d modules...", target, done, total)
		}
	}

	report, err := runner.Run(ctx, target, tt, opts)
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "\rprobing %s: done (%s)          \n", target, report.Meta.Duration)
	}

	switch strings.ToLower(probeOutputFmt) {
	case "json":
		return output.WriteProbe(w, report)
	default:
		output.ProbeReport(w, report)
	}
	return nil
}

func runBatchProbe(ctx context.Context, runner *investigate.Runner, opts investigate.RunOptions, w *os.File) error {
	f, err := os.Open(probeBatch)
	if err != nil {
		return fmt.Errorf("open batch file: %w", err)
	}
	defer f.Close()

	batchOpts := investigate.BatchOptions{
		RunOptions: opts,
		Parallel:   probeParallel,
	}
	if !quiet {
		batchOpts.Progress = func(done, total int, target string) {
			fmt.Fprintf(os.Stderr, "\rbatch: %d/%d targets (latest: %s)...", done, total, target)
		}
	}

	results, err := runner.RunBatch(ctx, f, batchOpts)
	if err != nil {
		return err
	}

	if !quiet {
		br := investigate.NewBatchReport(results)
		fmt.Fprintf(os.Stderr, "\rbatch: %d targets (%d ok, %d failed)         \n", br.Total, br.OK, br.Failed)
	}

	switch strings.ToLower(probeOutputFmt) {
	case "json":
		return output.WriteProbeBatch(w, results)
	default:
		output.ProbeBatchReport(w, results)
	}
	return nil
}

func listModules(runner *investigate.Runner) error {
	mods := runner.ListModules()
	fmt.Printf("%-15s %-50s %s\n", "MODULE", "DESCRIPTION", "TARGET TYPES")
	fmt.Printf("%-15s %-50s %s\n", "──────", "───────────", "────────────")
	for _, m := range mods {
		var types []string
		for _, t := range m.TargetTypes() {
			types = append(types, string(t))
		}
		fmt.Printf("%-15s %-50s %s\n", m.Name(), m.Description(), strings.Join(types, ", "))
	}
	return nil
}
