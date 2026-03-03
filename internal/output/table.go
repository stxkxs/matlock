package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/stxkxs/matlock/internal/cloud"
)

var (
	critStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	highStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600"))
	medStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	lowStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	headerStyle = lipgloss.NewStyle().Bold(true)
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	greenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00AA00"))
)

func colorSeverity(s cloud.Severity) lipgloss.Style {
	switch s {
	case cloud.SeverityCritical:
		return critStyle
	case cloud.SeverityHigh:
		return highStyle
	case cloud.SeverityMedium:
		return medStyle
	case cloud.SeverityLow:
		return lowStyle
	default:
		return infoStyle
	}
}

// IAMFindings renders a findings table to w, followed by a severity summary line.
func IAMFindings(w io.Writer, findings []cloud.Finding, totalPrincipals int) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PRINCIPAL"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		principal := ""
		if f.Principal != nil {
			principal = f.Principal.Name
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			sev, string(f.Type), principal, truncate(f.Detail, 80),
		)
	}
	tw.Flush()

	var crit, high, med int
	for _, f := range findings {
		switch f.Severity {
		case cloud.SeverityCritical:
			crit++
		case cloud.SeverityHigh:
			high++
		case cloud.SeverityMedium:
			med++
		}
	}
	summary := fmt.Sprintf("%s critical, %s high, %s medium across %d principals",
		critStyle.Render(fmt.Sprintf("%d", crit)),
		highStyle.Render(fmt.Sprintf("%d", high)),
		medStyle.Render(fmt.Sprintf("%d", med)),
		totalPrincipals,
	)
	fmt.Fprintf(w, "\n%s\n", summary)
}

// BucketFindings renders a storage findings table.
func BucketFindings(w io.Writer, findings []cloud.BucketFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("BUCKET"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.Provider, f.Bucket, truncate(f.Detail, 70),
		)
	}
	tw.Flush()
}

// OrphanResources renders an orphan resources table with a TOTAL row at the bottom.
func OrphanResources(w io.Writer, orphans []cloud.OrphanResource) {
	if len(orphans) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no orphaned resources found"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("KIND"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("NAME"),
		headerStyle.Render("REGION"),
		headerStyle.Render("$/MONTH"),
		headerStyle.Render("DETAIL"),
	)
	var total float64
	for _, o := range orphans {
		cost := fmt.Sprintf("$%.2f", o.MonthlyCost)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			string(o.Kind), o.Provider, o.Name, o.Region,
			highStyle.Render(cost), truncate(o.Detail, 60),
		)
		total += o.MonthlyCost
	}
	fmt.Fprintf(tw, "%s\t\t\t\t%s\t\n",
		headerStyle.Render("TOTAL"),
		headerStyle.Render(fmt.Sprintf("$%.2f", total)),
	)
	tw.Flush()
}

// CostDiffs renders cost diff tables for each provider.
func CostDiffs(w io.Writer, diffs []cloud.CostDiff) {
	for _, d := range diffs {
		fmt.Fprintf(w, "\n%s  %s → %s  vs  %s → %s\n",
			headerStyle.Render("["+d.Provider+"]"),
			d.BeforeStart.Format("2006-01-02"), d.BeforeEnd.Format("2006-01-02"),
			d.AfterStart.Format("2006-01-02"), d.AfterEnd.Format("2006-01-02"),
		)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			headerStyle.Render("SERVICE"),
			headerStyle.Render("BEFORE"),
			headerStyle.Render("AFTER"),
			headerStyle.Render("DELTA"),
			headerStyle.Render("CHANGE%"),
		)
		for _, e := range d.Entries {
			deltaStr := fmt.Sprintf("%+.2f", e.Delta)
			pctStr := fmt.Sprintf("%+.1f%%", e.PctChange)
			var deltaStyled, pctStyled string
			if e.PctChange > 10 {
				deltaStyled = critStyle.Render(deltaStr)
				pctStyled = critStyle.Render(pctStr)
			} else if e.Delta < 0 {
				deltaStyled = greenStyle.Render(deltaStr)
				pctStyled = greenStyle.Render(pctStr)
			} else {
				deltaStyled = deltaStr
				pctStyled = pctStr
			}
			fmt.Fprintf(tw, "%s\t$%.2f\t$%.2f\t%s\t%s\n",
				e.Service, e.Before, e.After, deltaStyled, pctStyled,
			)
		}
		tw.Flush()
		fmt.Fprintf(w, "\nTotal: $%.2f → $%.2f  (%+.2f)\n", d.TotalBefore, d.TotalAfter, d.TotalDelta)
	}
}

// NetworkFindings renders a network security findings table.
func NetworkFindings(w io.Writer, findings []cloud.NetworkFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("REGION"),
		headerStyle.Render("PORT"),
		headerStyle.Render("CIDR"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.Provider, f.Resource, f.Region, f.Port, f.CIDR, truncate(f.Detail, 60),
		)
	}
	tw.Flush()
}

// CertFindings renders a certificate expiry findings table.
func CertFindings(w io.Writer, findings []cloud.CertFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("STATUS"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("DOMAIN"),
		headerStyle.Render("REGION"),
		headerStyle.Render("EXPIRES"),
		headerStyle.Render("DAYS"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		expires := f.ExpiresAt.Format("2006-01-02")
		days := fmt.Sprintf("%d", f.DaysLeft)
		if f.DaysLeft < 0 {
			days = critStyle.Render(days)
			expires = critStyle.Render(expires)
		} else if f.DaysLeft < 7 {
			days = critStyle.Render(days)
		} else if f.DaysLeft < 30 {
			days = highStyle.Render(days)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Status), f.Provider, f.Domain, f.Region, expires, days,
		)
	}
	tw.Flush()
}

// TagFindings renders a missing tags findings table.
func TagFindings(w io.Writer, findings []cloud.TagFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("REGION"),
		headerStyle.Render("MISSING"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		missing := ""
		for i, t := range f.MissingTags {
			if i > 0 {
				missing += ", "
			}
			missing += t
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, f.Provider, f.ResourceType, f.ResourceID, f.Region, missing,
		)
	}
	tw.Flush()
}

func truncate(s string, n int) string {
	if n < 4 || len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
