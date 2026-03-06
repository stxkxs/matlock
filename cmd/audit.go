package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stxkxs/matlock/internal/audit"
	"github.com/stxkxs/matlock/internal/cloud"
	cloudaws "github.com/stxkxs/matlock/internal/cloud/aws"
	cloudazure "github.com/stxkxs/matlock/internal/cloud/azure"
	cloudgcp "github.com/stxkxs/matlock/internal/cloud/gcp"
	"github.com/stxkxs/matlock/internal/output"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run all security and cost scans in one shot",
	Long: `Run a unified full-spectrum audit across IAM, storage, network, orphans,
certs, tags, and secrets. Produces a single combined report.

Skip specific domains with --skip, e.g. --skip iam,certs`,
	RunE: runAudit,
}

var (
	auditProviders    []string
	auditSkip         []string
	auditSeverity     string
	auditOutputFmt    string
	auditOutputFile   string
	auditIAMDays      int
	auditCertDays     int
	auditRequiredTags []string
	auditConcurrency  int
)

func init() {
	auditCmd.Flags().StringSliceVar(&auditProviders, "provider", []string{}, "cloud providers (aws,gcp,azure); auto-detect if empty")
	auditCmd.Flags().StringSliceVar(&auditSkip, "skip", []string{}, "domains to skip (iam,storage,network,orphans,certs,tags,secrets)")
	auditCmd.Flags().StringVar(&auditSeverity, "severity", "LOW", "minimum severity to report")
	auditCmd.Flags().StringVar(&auditOutputFmt, "output", "table", "output format: table, json, sarif")
	auditCmd.Flags().StringVar(&auditOutputFile, "output-file", "", "write output to file")
	auditCmd.Flags().IntVar(&auditIAMDays, "iam-days", 90, "IAM audit log lookback period in days")
	auditCmd.Flags().IntVar(&auditCertDays, "cert-days", 90, "certificate expiry warning threshold in days")
	auditCmd.Flags().StringSliceVar(&auditRequiredTags, "require-tags", []string{}, "required tags for tag audit (comma-separated)")
	auditCmd.Flags().IntVar(&auditConcurrency, "concurrency", 10, "max parallel goroutines for IAM scanning")
}

func runAudit(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	skip := make(map[string]bool)
	for _, s := range auditSkip {
		skip[strings.ToLower(s)] = true
	}

	providers, err := buildAuditProviders(ctx, auditProviders)
	if err != nil {
		return err
	}

	report, err := audit.Run(ctx, providers, audit.Options{
		Skip:         skip,
		MinSeverity:  cloud.Severity(strings.ToUpper(auditSeverity)),
		IAMDays:      auditIAMDays,
		CertDays:     auditCertDays,
		RequiredTags: auditRequiredTags,
		Concurrency:  auditConcurrency,
		Quiet:        quiet,
	})
	if err != nil {
		return err
	}

	w := os.Stdout
	if auditOutputFile != "" {
		f, err := os.Create(auditOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	switch strings.ToLower(auditOutputFmt) {
	case "json":
		return output.WriteAudit(w, report)
	case "sarif":
		return output.WriteAuditSARIF(w, report, Version)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nAudit complete in %s\n\n", report.Duration)
		}
		output.AuditReport(w, report)
	}
	return nil
}

func buildAuditProviders(ctx context.Context, names []string) (audit.Providers, error) {
	type multiProvider interface {
		cloud.Provider
		cloud.IAMProvider
		cloud.StorageProvider
		cloud.NetworkProvider
		cloud.OrphansProvider
		cloud.CertProvider
		cloud.TagProvider
		cloud.SecretsProvider
	}

	var multi []multiProvider
	if len(names) == 0 {
		// Auto-detect
		if p, err := cloudaws.New(ctx); err == nil && p.Detect(ctx) {
			multi = append(multi, p)
		}
		if p, err := cloudgcp.New(ctx, ""); err == nil && p.Detect(ctx) {
			multi = append(multi, p)
		}
		if p, err := cloudazure.New(ctx, ""); err == nil && p.Detect(ctx) {
			multi = append(multi, p)
		}
		if len(multi) == 0 {
			return audit.Providers{}, fmt.Errorf("no cloud provider credentials detected")
		}
	} else {
		for _, name := range names {
			switch strings.ToLower(name) {
			case "aws":
				p, err := cloudaws.New(ctx)
				if err != nil {
					return audit.Providers{}, fmt.Errorf("aws: %w", err)
				}
				multi = append(multi, p)
			case "gcp":
				p, err := cloudgcp.New(ctx, "")
				if err != nil {
					return audit.Providers{}, fmt.Errorf("gcp: %w", err)
				}
				multi = append(multi, p)
			case "azure":
				p, err := cloudazure.New(ctx, "")
				if err != nil {
					return audit.Providers{}, fmt.Errorf("azure: %w", err)
				}
				multi = append(multi, p)
			default:
				return audit.Providers{}, fmt.Errorf("unknown provider: %s", name)
			}
		}
	}

	var providers audit.Providers
	for _, p := range multi {
		providers.IAM = append(providers.IAM, p)
		providers.Storage = append(providers.Storage, p)
		providers.Network = append(providers.Network, p)
		providers.Orphans = append(providers.Orphans, p)
		providers.Certs = append(providers.Certs, p)
		providers.Tags = append(providers.Tags, p)
		providers.Secrets = append(providers.Secrets, p)
	}
	return providers, nil
}
