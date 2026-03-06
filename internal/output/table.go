package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/compliance"
	"github.com/stxkxs/matlock/internal/investigate"
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

// DriftResults renders a drift detection results table.
func DriftResults(w io.Writer, results []cloud.DriftResult) {
	if len(results) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no resources checked"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("STATUS"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("ID"),
		headerStyle.Render("DETAIL"),
	)
	for _, r := range results {
		var statusStyled string
		switch r.Status {
		case cloud.DriftInSync:
			statusStyled = greenStyle.Render("IN_SYNC")
		case cloud.DriftModified:
			statusStyled = critStyle.Render("MODIFIED")
		case cloud.DriftDeleted:
			statusStyled = critStyle.Render("DELETED")
		case cloud.DriftError:
			statusStyled = medStyle.Render("ERROR")
		}

		detail := r.Detail
		if len(r.Fields) > 0 && detail == "" {
			var parts []string
			for _, f := range r.Fields {
				parts = append(parts, fmt.Sprintf("%s: %s→%s", f.Field, f.Expected, f.Actual))
			}
			detail = strings.Join(parts, "; ")
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			statusStyled, r.ResourceName, r.ResourceType, truncate(r.ResourceID, 30), truncate(detail, 60),
		)
	}
	tw.Flush()
}

// ComplianceReport renders a compliance evaluation table.
func ComplianceReport(w io.Writer, report compliance.ComplianceReport) {
	if len(report.Results) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no controls evaluated"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("STATUS"),
		headerStyle.Render("ID"),
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TITLE"),
		headerStyle.Render("DETAIL"),
	)
	for _, r := range report.Results {
		var statusStyled string
		switch r.Status {
		case compliance.StatusPass:
			statusStyled = greenStyle.Render("PASS")
		case compliance.StatusFail:
			statusStyled = critStyle.Render("FAIL")
		default:
			statusStyled = dimStyle.Render("N/A")
		}
		sev := colorSeverity(r.Control.Severity).Render(string(r.Control.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			statusStyled, r.Control.ID, sev, truncate(r.Control.Title, 55), truncate(r.Detail, 50),
		)
	}
	tw.Flush()

	summary := fmt.Sprintf("\n%s passed, %s failed, %s not evaluated (%d total)",
		greenStyle.Render(fmt.Sprintf("%d", report.Summary.Passed)),
		critStyle.Render(fmt.Sprintf("%d", report.Summary.Failed)),
		dimStyle.Render(fmt.Sprintf("%d", report.Summary.NotEvaluated)),
		report.Summary.Total,
	)
	fmt.Fprintln(w, summary)
}

// SecretFindings renders a secret findings table.
func SecretFindings(w io.Writer, findings []cloud.SecretFinding) {
	if len(findings) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no findings"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("SEVERITY"),
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("RESOURCE"),
		headerStyle.Render("KEY"),
		headerStyle.Render("MATCH"),
		headerStyle.Render("DETAIL"),
	)
	for _, f := range findings {
		sev := colorSeverity(f.Severity).Render(string(f.Severity))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			sev, string(f.Type), f.Provider, f.Resource, f.Key, f.Match, truncate(f.Detail, 60),
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
	summary := fmt.Sprintf("\n%s critical, %s high, %s medium",
		critStyle.Render(fmt.Sprintf("%d", crit)),
		highStyle.Render(fmt.Sprintf("%d", high)),
		medStyle.Render(fmt.Sprintf("%d", med)),
	)
	fmt.Fprintln(w, summary)
}

// ProbeReport renders a full probe report with per-module detail sections.
func ProbeReport(w io.Writer, report *investigate.Report) {
	fmt.Fprintf(w, "\n%s  %s (%s)  %s\n",
		headerStyle.Render("[probe]"),
		headerStyle.Render(report.Target),
		string(report.Type),
		dimStyle.Render(report.Meta.Duration),
	)

	// Render modules in a logical display order.
	for _, name := range probeDisplayOrder {
		mr, ok := report.Results[name]
		if !ok {
			continue
		}
		probeSection(w, name, mr)
	}
	// Render any modules not in the display order list.
	rendered := make(map[string]bool, len(probeDisplayOrder))
	for _, n := range probeDisplayOrder {
		rendered[n] = true
	}
	names := make([]string, 0)
	for name := range report.Results {
		if !rendered[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		probeSection(w, name, report.Results[name])
	}

	// Summary line.
	fmt.Fprintf(w, "\n%d modules: %s ok, %s failed\n",
		report.Summary.ModulesRun,
		greenStyle.Render(fmt.Sprintf("%d", report.Summary.ModulesOK)),
		critStyle.Render(fmt.Sprintf("%d", report.Summary.ModulesFailed)),
	)

	if report.Score != nil {
		probeScoreTable(w, report.Score)
	}
}

var probeDisplayOrder = []string{
	"dns", "ssl", "http", "ports", "whois", "subdomain", "crt",
	"cors", "waf", "tech", "dnssec", "files", "methods", "dirs",
	"jsanalysis", "favicon", "emailsec", "takeover",
	"shodan", "virustotal", "sectrails", "wayback",
	"reverseip", "asn", "ip",
}

func probeSection(w io.Writer, name string, mr investigate.ModuleResult) {
	title := strings.ToUpper(name)
	fmt.Fprintf(w, "\n%s", headerStyle.Render("─── "+title+" "))
	if mr.Status == "failed" {
		fmt.Fprintf(w, " %s", critStyle.Render("FAILED"))
		if mr.Error != "" {
			fmt.Fprintf(w, "  %s", dimStyle.Render(mr.Error))
		}
		fmt.Fprintln(w)
		return
	}
	if mr.Status == "partial" {
		fmt.Fprintf(w, " %s", medStyle.Render("PARTIAL"))
	}
	fmt.Fprintf(w, "  %s\n", dimStyle.Render(mr.Duration))

	if mr.Data == nil || string(mr.Data) == "null" {
		return
	}

	// Dispatch to module-specific renderer.
	var data map[string]json.RawMessage
	if err := json.Unmarshal(mr.Data, &data); err != nil {
		return
	}

	switch name {
	case "dns":
		probePrintDNS(w, data)
	case "ssl":
		probePrintSSL(w, data)
	case "http":
		probePrintHTTP(w, data)
	case "ports":
		probePrintPorts(w, data)
	case "whois":
		probePrintWhois(w, data)
	case "subdomain":
		probePrintSubdomains(w, data)
	case "crt":
		probePrintCRT(w, data)
	case "cors":
		probePrintCORS(w, data)
	case "waf":
		probePrintWAF(w, data)
	case "tech":
		probePrintTech(w, data)
	case "dnssec":
		probePrintDNSSEC(w, data)
	case "files":
		probePrintFiles(w, data)
	case "methods":
		probePrintMethods(w, data)
	case "dirs":
		probePrintDirs(w, data)
	case "jsanalysis":
		probePrintJS(w, data)
	case "favicon":
		probePrintFavicon(w, data)
	case "emailsec":
		probePrintEmailSec(w, data)
	case "takeover":
		probePrintTakeover(w, data)
	case "shodan":
		probePrintShodan(w, data)
	case "virustotal":
		probePrintVT(w, data)
	case "sectrails":
		probePrintSecTrails(w, data)
	case "wayback":
		probePrintWayback(w, data)
	case "reverseip":
		probePrintReverseIP(w, data)
	case "asn":
		probePrintASN(w, data)
	case "ip":
		probePrintIP(w, data)
	default:
		probePrintGeneric(w, data)
	}
}

// ── Per-module renderers ──

func probePrintDNS(w io.Writer, data map[string]json.RawMessage) {
	probeKVList(w, "A", data, "a")
	probeKVList(w, "AAAA", data, "aaaa")
	probeKVList(w, "NS", data, "ns")
	probeKVList(w, "TXT", data, "txt")

	if raw, ok := data["mx"]; ok {
		var mx []struct {
			Host     string `json:"host"`
			Priority int    `json:"priority"`
		}
		if json.Unmarshal(raw, &mx) == nil && len(mx) > 0 {
			fmt.Fprintf(w, "  %-14s", headerStyle.Render("MX"))
			for i, r := range mx {
				if i > 0 {
					fmt.Fprintf(w, "  %-14s", "")
				}
				fmt.Fprintf(w, "%s (pri %d)\n", r.Host, r.Priority)
			}
		}
	}
	if raw, ok := data["caa"]; ok {
		var caa []struct {
			Tag   string `json:"tag"`
			Value string `json:"value"`
		}
		if json.Unmarshal(raw, &caa) == nil && len(caa) > 0 {
			fmt.Fprintf(w, "  %-14s", headerStyle.Render("CAA"))
			for i, r := range caa {
				if i > 0 {
					fmt.Fprintf(w, "  %-14s", "")
				}
				fmt.Fprintf(w, "%s %s\n", r.Tag, r.Value)
			}
		}
	}
	probeKV(w, "DMARC", data, "dmarc")
	if raw, ok := data["dkim"]; ok {
		var dkim map[string]string
		if json.Unmarshal(raw, &dkim) == nil && len(dkim) > 0 {
			first := true
			for sel, rec := range dkim {
				if first {
					fmt.Fprintf(w, "  %-14s%s: %s\n", headerStyle.Render("DKIM"), sel, truncate(rec, 60))
					first = false
				} else {
					fmt.Fprintf(w, "  %-14s%s: %s\n", "", sel, truncate(rec, 60))
				}
			}
		}
	}
}

func probePrintSSL(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["certificates"]; ok {
		var certs []struct {
			Host       string   `json:"host"`
			Connected  bool     `json:"connected"`
			Subject    string   `json:"subject"`
			Issuer     string   `json:"issuer"`
			SANs       []string `json:"sans"`
			NotAfter   string   `json:"not_after"`
			DaysLeft   int      `json:"days_left"`
			Expired    bool     `json:"expired"`
			TLSVersion string   `json:"tls_version"`
			SigAlg     string   `json:"sig_alg"`
			Error      string   `json:"error,omitempty"`
		}
		if json.Unmarshal(raw, &certs) == nil {
			for _, c := range certs {
				if !c.Connected {
					fmt.Fprintf(w, "  %s  %s\n", c.Host, dimStyle.Render(c.Error))
					continue
				}
				expiryStyle := greenStyle
				if c.Expired {
					expiryStyle = critStyle
				} else if c.DaysLeft < 30 {
					expiryStyle = highStyle
				}
				fmt.Fprintf(w, "  %s\n", headerStyle.Render(c.Host))
				fmt.Fprintf(w, "    Subject     %s\n", c.Subject)
				fmt.Fprintf(w, "    Issuer      %s\n", c.Issuer)
				fmt.Fprintf(w, "    Expires     %s (%s)\n",
					c.NotAfter,
					expiryStyle.Render(fmt.Sprintf("%d days", c.DaysLeft)),
				)
				fmt.Fprintf(w, "    TLS         %s  %s\n", c.TLSVersion, dimStyle.Render(c.SigAlg))
				if len(c.SANs) > 0 {
					fmt.Fprintf(w, "    SANs        %s\n", strings.Join(c.SANs, ", "))
				}
			}
		}
	}
}

func probePrintHTTP(w io.Writer, data map[string]json.RawMessage) {
	httpsOK := probeJSONBool(data, "https_reachable")
	redirects := probeJSONBool(data, "redirects_https")
	if httpsOK {
		fmt.Fprintf(w, "  %-20s%s\n", "HTTPS", greenStyle.Render("reachable"))
	} else {
		fmt.Fprintf(w, "  %-20s%s\n", "HTTPS", critStyle.Render("not reachable"))
	}
	if redirects {
		fmt.Fprintf(w, "  %-20s%s\n", "HTTP→HTTPS", greenStyle.Render("yes"))
	}
	probeKV(w, "Server", data, "server")

	// Security headers
	if raw, ok := data["security_headers"]; ok {
		var headers map[string]string
		if json.Unmarshal(raw, &headers) == nil {
			secHeaders := []string{
				"strict-transport-security", "content-security-policy",
				"x-frame-options", "x-content-type-options",
				"referrer-policy", "permissions-policy",
			}
			fmt.Fprintf(w, "  %s\n", headerStyle.Render("Security Headers"))
			for _, h := range secHeaders {
				if v, ok := headers[h]; ok && v != "" {
					fmt.Fprintf(w, "    %s %s  %s\n", greenStyle.Render("✓"), h, dimStyle.Render(truncate(v, 50)))
				} else {
					fmt.Fprintf(w, "    %s %s\n", critStyle.Render("✗"), h)
				}
			}
		}
	}

	// Infrastructure
	if raw, ok := data["infrastructure"]; ok {
		var infra map[string]string
		if json.Unmarshal(raw, &infra) == nil && len(infra) > 0 {
			fmt.Fprintf(w, "  %s\n", headerStyle.Render("Infrastructure"))
			for k, v := range infra {
				fmt.Fprintf(w, "    %-20s%s\n", k, v)
			}
		}
	}
}

func probePrintPorts(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["open"]; ok {
		var ports []struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
			State   string `json:"state"`
		}
		if json.Unmarshal(raw, &ports) == nil {
			if len(ports) == 0 {
				fmt.Fprintf(w, "  %s\n", dimStyle.Render("no open ports found"))
				return
			}
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "  %s\t%s\t%s\n",
				headerStyle.Render("PORT"),
				headerStyle.Render("SERVICE"),
				headerStyle.Render("STATE"),
			)
			for _, p := range ports {
				fmt.Fprintf(tw, "  %s\t%s\t%s\n",
					greenStyle.Render(fmt.Sprintf("%d", p.Port)),
					p.Service, p.State,
				)
			}
			tw.Flush()
		}
	}
	var scanned int
	if raw, ok := data["total_scanned"]; ok {
		json.Unmarshal(raw, &scanned)
	}
	var open int
	if raw, ok := data["open"]; ok {
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) == nil {
			open = len(arr)
		}
	}
	fmt.Fprintf(w, "  %d open / %d scanned\n", open, scanned)
}

func probePrintWhois(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["parsed"]; ok && string(raw) != "null" {
		var parsed struct {
			Registrar      string   `json:"registrar"`
			CreationDate   string   `json:"creation_date"`
			ExpirationDate string   `json:"expiration_date"`
			NameServers    []string `json:"name_servers"`
			Registrant     string   `json:"registrant"`
			Country        string   `json:"country"`
		}
		if json.Unmarshal(raw, &parsed) == nil {
			if parsed.Registrar != "" {
				fmt.Fprintf(w, "  %-18s%s\n", "Registrar", parsed.Registrar)
			}
			if parsed.Registrant != "" {
				fmt.Fprintf(w, "  %-18s%s\n", "Registrant", parsed.Registrant)
			}
			if parsed.Country != "" {
				fmt.Fprintf(w, "  %-18s%s\n", "Country", parsed.Country)
			}
			if parsed.CreationDate != "" {
				fmt.Fprintf(w, "  %-18s%s\n", "Created", parsed.CreationDate)
			}
			if parsed.ExpirationDate != "" {
				fmt.Fprintf(w, "  %-18s%s\n", "Expires", parsed.ExpirationDate)
			}
			if len(parsed.NameServers) > 0 {
				fmt.Fprintf(w, "  %-18s%s\n", "Name Servers", strings.Join(parsed.NameServers, ", "))
			}
		}
	}
}

func probePrintSubdomains(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["found"]; ok {
		var found []struct {
			FQDN  string   `json:"fqdn"`
			IPs   []string `json:"ips"`
			CNAME string   `json:"cname,omitempty"`
		}
		if json.Unmarshal(raw, &found) == nil {
			if len(found) == 0 {
				fmt.Fprintf(w, "  %s\n", dimStyle.Render("none found"))
				return
			}
			for _, s := range found {
				ip := strings.Join(s.IPs, ", ")
				if s.CNAME != "" {
					fmt.Fprintf(w, "  %-30s %s %s\n", s.FQDN, dimStyle.Render("→"), s.CNAME+" ("+ip+")")
				} else {
					fmt.Fprintf(w, "  %-30s %s\n", s.FQDN, ip)
				}
			}
		}
	}
	probeKVInt(w, "Checked", data, "total_checked")
}

func probePrintCRT(w io.Writer, data map[string]json.RawMessage) {
	probeKVList(w, "Subdomains", data, "subdomains")
	probeKVInt(w, "Total", data, "total")
}

func probePrintCORS(w io.Writer, data map[string]json.RawMessage) {
	vuln := probeJSONBool(data, "vulnerable")
	if !vuln {
		fmt.Fprintf(w, "  %s\n", greenStyle.Render("no CORS misconfigurations detected"))
		return
	}
	var risk string
	if raw, ok := data["risk"]; ok {
		json.Unmarshal(raw, &risk)
	}
	riskStyle := medStyle
	if risk == "critical" || risk == "high" {
		riskStyle = critStyle
	}
	fmt.Fprintf(w, "  Risk: %s\n", riskStyle.Render(risk))

	if raw, ok := data["tests"]; ok {
		var tests []struct {
			Origin        string `json:"origin"`
			Misconfigured bool   `json:"misconfigured"`
			Detail        string `json:"detail"`
		}
		if json.Unmarshal(raw, &tests) == nil {
			for _, t := range tests {
				if t.Misconfigured {
					fmt.Fprintf(w, "  %s %s  %s\n", critStyle.Render("✗"), t.Origin, t.Detail)
				}
			}
		}
	}
}

func probePrintWAF(w io.Writer, data map[string]json.RawMessage) {
	detected := probeJSONBool(data, "detected")
	if !detected {
		fmt.Fprintf(w, "  %s\n", dimStyle.Render("no WAF/CDN detected"))
		return
	}
	if raw, ok := data["providers"]; ok {
		var providers []struct {
			Name       string   `json:"name"`
			Indicators []string `json:"indicators"`
		}
		if json.Unmarshal(raw, &providers) == nil {
			for _, p := range providers {
				fmt.Fprintf(w, "  %s  %s\n", headerStyle.Render(p.Name), dimStyle.Render(strings.Join(p.Indicators, ", ")))
			}
		}
	}
	var conf string
	if raw, ok := data["confidence"]; ok {
		json.Unmarshal(raw, &conf)
	}
	fmt.Fprintf(w, "  Confidence: %s\n", conf)
}

func probePrintTech(w io.Writer, data map[string]json.RawMessage) {
	printList := func(label, key string) {
		if raw, ok := data[key]; ok {
			var items []string
			if json.Unmarshal(raw, &items) == nil && len(items) > 0 {
				fmt.Fprintf(w, "  %-18s%s\n", headerStyle.Render(label), strings.Join(items, ", "))
			}
		}
	}
	printList("Frontend", "frontend")
	printList("Analytics", "analytics")
	printList("Infrastructure", "infrastructure")
}

func probePrintDNSSEC(w io.Writer, data map[string]json.RawMessage) {
	enabled := probeJSONBool(data, "enabled")
	if !enabled {
		fmt.Fprintf(w, "  %s\n", dimStyle.Render("DNSSEC not enabled"))
		return
	}
	valid := probeJSONBool(data, "valid")
	if valid {
		fmt.Fprintf(w, "  %s\n", greenStyle.Render("DNSSEC enabled and valid"))
	} else {
		fmt.Fprintf(w, "  %s\n", medStyle.Render("DNSSEC enabled but not fully validated"))
	}
	probeKV(w, "Algorithm", data, "algorithm")
	probeKVInt(w, "Keys", data, "key_count")
	fmt.Fprintf(w, "  %-18sHas DNSKEY: %v, Has DS: %v, Has RRSIG: %v\n",
		"", probeJSONBool(data, "has_dnskey"), probeJSONBool(data, "has_ds"), probeJSONBool(data, "has_rrsig"))
}

func probePrintFiles(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["files"]; ok {
		var files []struct {
			Path   string `json:"path"`
			Status int    `json:"status"`
			Exists bool   `json:"exists"`
		}
		if json.Unmarshal(raw, &files) == nil {
			for _, f := range files {
				if f.Exists {
					fmt.Fprintf(w, "  %s %s  %s\n", greenStyle.Render("✓"), f.Path, dimStyle.Render(fmt.Sprintf("%d", f.Status)))
				} else {
					fmt.Fprintf(w, "  %s %s\n", dimStyle.Render("✗"), dimStyle.Render(f.Path))
				}
			}
		}
	}
}

func probePrintMethods(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["risky"]; ok {
		var risky []struct {
			Path   string `json:"path"`
			Method string `json:"method"`
			Risk   string `json:"risk"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(raw, &risky) == nil && len(risky) > 0 {
			for _, r := range risky {
				rStyle := medStyle
				if r.Risk == "high" || r.Risk == "critical" {
					rStyle = critStyle
				}
				fmt.Fprintf(w, "  %s  %s %s  %s\n", rStyle.Render(r.Risk), r.Method, r.Path, dimStyle.Render(r.Detail))
			}
			return
		}
	}
	fmt.Fprintf(w, "  %s\n", greenStyle.Render("no risky HTTP methods detected"))
}

func probePrintDirs(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["found"]; ok {
		var found []struct {
			Path     string `json:"path"`
			Status   int    `json:"status"`
			Severity string `json:"severity"`
			Category string `json:"category"`
		}
		if json.Unmarshal(raw, &found) == nil {
			if len(found) == 0 {
				fmt.Fprintf(w, "  %s\n", greenStyle.Render("no exposed directories or files"))
				return
			}
			for _, f := range found {
				sevStyle := dimStyle
				switch f.Severity {
				case "critical":
					sevStyle = critStyle
				case "high":
					sevStyle = highStyle
				case "medium":
					sevStyle = medStyle
				}
				fmt.Fprintf(w, "  %s  %-35s %d  %s\n",
					sevStyle.Render(fmt.Sprintf("%-8s", f.Severity)),
					f.Path, f.Status, dimStyle.Render(f.Category),
				)
			}
		}
	}
}

func probePrintJS(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["secrets"]; ok {
		var secrets []struct {
			Type  string `json:"type"`
			File  string `json:"file"`
			Match string `json:"match"`
		}
		if json.Unmarshal(raw, &secrets) == nil && len(secrets) > 0 {
			fmt.Fprintf(w, "  %s\n", critStyle.Render(fmt.Sprintf("%d secrets found!", len(secrets))))
			for _, s := range secrets {
				fmt.Fprintf(w, "    %s  %s  %s\n", critStyle.Render(s.Type), dimStyle.Render(s.File), truncate(s.Match, 40))
			}
		} else {
			fmt.Fprintf(w, "  %s\n", greenStyle.Render("no secrets found"))
		}
	}
	if raw, ok := data["scripts"]; ok {
		var scripts []json.RawMessage
		if json.Unmarshal(raw, &scripts) == nil {
			fmt.Fprintf(w, "  %d scripts analyzed\n", len(scripts))
		}
	}
	if raw, ok := data["endpoints"]; ok {
		var endpoints []string
		if json.Unmarshal(raw, &endpoints) == nil && len(endpoints) > 0 {
			fmt.Fprintf(w, "  %d endpoints discovered\n", len(endpoints))
		}
	}
}

func probePrintFavicon(w io.Writer, data map[string]json.RawMessage) {
	probeKV(w, "MD5", data, "md5")
	if raw, ok := data["mmh3"]; ok {
		var mmh3 int32
		if json.Unmarshal(raw, &mmh3) == nil && mmh3 != 0 {
			fmt.Fprintf(w, "  %-18s%d\n", "MurmurHash3", mmh3)
		}
	}
	probeKV(w, "Shodan Query", data, "shodan_query")
}

func probePrintEmailSec(w io.Writer, data map[string]json.RawMessage) {
	var grade string
	if raw, ok := data["grade"]; ok {
		json.Unmarshal(raw, &grade)
	}
	gradeStyle := critStyle
	switch grade {
	case "A", "B":
		gradeStyle = greenStyle
	case "C":
		gradeStyle = medStyle
	case "D":
		gradeStyle = highStyle
	}
	fmt.Fprintf(w, "  Grade: %s\n", gradeStyle.Render(grade))

	// SPF
	if raw, ok := data["spf"]; ok && string(raw) != "null" {
		var spf struct {
			Record       string `json:"record"`
			AllQualifier string `json:"all_qualifier"`
			Strict       bool   `json:"strict"`
		}
		if json.Unmarshal(raw, &spf) == nil {
			icon := greenStyle.Render("✓")
			if !spf.Strict {
				icon = medStyle.Render("~")
			}
			fmt.Fprintf(w, "  %s SPF   %s  all=%s\n", icon, truncate(spf.Record, 50), spf.AllQualifier)
		}
	} else {
		fmt.Fprintf(w, "  %s SPF   %s\n", critStyle.Render("✗"), "not configured")
	}

	// DMARC
	if raw, ok := data["dmarc"]; ok && string(raw) != "null" {
		var dmarc struct {
			Policy string `json:"policy"`
			Record string `json:"record"`
		}
		if json.Unmarshal(raw, &dmarc) == nil {
			icon := greenStyle.Render("✓")
			if dmarc.Policy == "none" {
				icon = medStyle.Render("~")
			}
			fmt.Fprintf(w, "  %s DMARC p=%s  %s\n", icon, dmarc.Policy, truncate(dmarc.Record, 50))
		}
	} else {
		fmt.Fprintf(w, "  %s DMARC %s\n", critStyle.Render("✗"), "not configured")
	}

	// DKIM
	if raw, ok := data["dkim"]; ok {
		var dkim []struct {
			Selector string `json:"selector"`
			Found    bool   `json:"found"`
		}
		if json.Unmarshal(raw, &dkim) == nil {
			var foundSels []string
			for _, d := range dkim {
				if d.Found {
					foundSels = append(foundSels, d.Selector)
				}
			}
			if len(foundSels) > 0 {
				fmt.Fprintf(w, "  %s DKIM  selectors: %s\n", greenStyle.Render("✓"), strings.Join(foundSels, ", "))
			} else {
				fmt.Fprintf(w, "  %s DKIM  %s\n", critStyle.Render("✗"), "no selectors found")
			}
		}
	}

	// BIMI
	if raw, ok := data["bimi"]; ok && string(raw) != "null" {
		var bimi struct {
			Found bool   `json:"found"`
			Logo  string `json:"logo"`
		}
		if json.Unmarshal(raw, &bimi) == nil && bimi.Found {
			fmt.Fprintf(w, "  %s BIMI  logo: %s\n", greenStyle.Render("✓"), bimi.Logo)
		}
	}
}

func probePrintTakeover(w io.Writer, data map[string]json.RawMessage) {
	if raw, ok := data["vulnerable"]; ok {
		var vuln []struct {
			Subdomain string `json:"subdomain"`
			CNAME     string `json:"cname"`
			Service   string `json:"service"`
			Dangling  bool   `json:"dangling"`
			Risk      string `json:"risk"`
		}
		if json.Unmarshal(raw, &vuln) == nil && len(vuln) > 0 {
			for _, v := range vuln {
				rStyle := medStyle
				if v.Dangling {
					rStyle = critStyle
				}
				fmt.Fprintf(w, "  %s  %s → %s (%s)\n",
					rStyle.Render(v.Risk), v.Subdomain, v.CNAME, v.Service)
			}
			return
		}
	}
	probeKVInt(w, "Checked", data, "checked")
	fmt.Fprintf(w, "  %s\n", greenStyle.Render("no takeover risks found"))
}

func probePrintShodan(w io.Writer, data map[string]json.RawMessage) {
	probeKV(w, "IP", data, "ip")
	probeKV(w, "Org", data, "org")
	probeKV(w, "ISP", data, "isp")
	probeKV(w, "Country", data, "country")

	if raw, ok := data["ports"]; ok {
		var ports []int
		if json.Unmarshal(raw, &ports) == nil && len(ports) > 0 {
			strs := make([]string, len(ports))
			for i, p := range ports {
				strs[i] = fmt.Sprintf("%d", p)
			}
			fmt.Fprintf(w, "  %-18s%s\n", "Ports", strings.Join(strs, ", "))
		}
	}
	if raw, ok := data["vulns"]; ok {
		var vulns []string
		if json.Unmarshal(raw, &vulns) == nil && len(vulns) > 0 {
			fmt.Fprintf(w, "  %-18s%s\n", critStyle.Render("Vulns"), strings.Join(vulns, ", "))
		}
	}
	if raw, ok := data["services"]; ok {
		var services []struct {
			Port    int    `json:"port"`
			Product string `json:"product"`
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &services) == nil && len(services) > 0 {
			for _, s := range services {
				fmt.Fprintf(w, "    %d/%s %s\n", s.Port, s.Product, dimStyle.Render(s.Version))
			}
		}
	}
}

func probePrintVT(w io.Writer, data map[string]json.RawMessage) {
	var malicious, suspicious, harmless, undetected int
	if raw, ok := data["malicious"]; ok {
		json.Unmarshal(raw, &malicious)
	}
	if raw, ok := data["suspicious"]; ok {
		json.Unmarshal(raw, &suspicious)
	}
	if raw, ok := data["harmless"]; ok {
		json.Unmarshal(raw, &harmless)
	}
	if raw, ok := data["undetected"]; ok {
		json.Unmarshal(raw, &undetected)
	}
	malStyle := greenStyle
	if malicious > 0 {
		malStyle = critStyle
	}
	fmt.Fprintf(w, "  Malicious: %s  Suspicious: %d  Harmless: %d  Undetected: %d\n",
		malStyle.Render(fmt.Sprintf("%d", malicious)), suspicious, harmless, undetected,
	)
	probeKVInt(w, "Reputation", data, "reputation")
}

func probePrintSecTrails(w io.Writer, data map[string]json.RawMessage) {
	probeKV(w, "Hostname", data, "hostname")
	probeKVInt(w, "Alexa Rank", data, "alexa_rank")
	probeKVList(w, "Subdomains", data, "subdomains")
}

func probePrintWayback(w io.Writer, data map[string]json.RawMessage) {
	probeKVInt(w, "Snapshots", data, "total")
	if raw, ok := data["snapshots"]; ok {
		var snaps []struct {
			Timestamp string `json:"timestamp"`
			URL       string `json:"url"`
		}
		if json.Unmarshal(raw, &snaps) == nil && len(snaps) > 0 {
			limit := len(snaps)
			if limit > 10 {
				limit = 10
			}
			for _, s := range snaps[:limit] {
				fmt.Fprintf(w, "  %s  %s\n", dimStyle.Render(s.Timestamp), truncate(s.URL, 70))
			}
			if len(snaps) > 10 {
				fmt.Fprintf(w, "  %s\n", dimStyle.Render(fmt.Sprintf("... and %d more", len(snaps)-10)))
			}
		}
	}
}

func probePrintReverseIP(w io.Writer, data map[string]json.RawMessage) {
	probeKV(w, "IP", data, "ip")
	if raw, ok := data["domains"]; ok {
		var domains []string
		if json.Unmarshal(raw, &domains) == nil {
			fmt.Fprintf(w, "  %d co-hosted domains\n", len(domains))
			limit := len(domains)
			if limit > 20 {
				limit = 20
			}
			for _, d := range domains[:limit] {
				fmt.Fprintf(w, "    %s\n", d)
			}
			if len(domains) > 20 {
				fmt.Fprintf(w, "    %s\n", dimStyle.Render(fmt.Sprintf("... and %d more", len(domains)-20)))
			}
		}
	}
}

func probePrintASN(w io.Writer, data map[string]json.RawMessage) {
	probeKV(w, "ASN", data, "asn")
	probeKV(w, "Name", data, "asn_name")
	probeKV(w, "Prefix", data, "prefix")
	probeKV(w, "Country", data, "country")
	probeKV(w, "Registry", data, "registry")
	if raw, ok := data["prefixes"]; ok {
		var prefixes []struct {
			Prefix string `json:"prefix"`
			Name   string `json:"name"`
		}
		if json.Unmarshal(raw, &prefixes) == nil && len(prefixes) > 0 {
			fmt.Fprintf(w, "  %d announced prefixes\n", len(prefixes))
		}
	}
}

func probePrintIP(w io.Writer, data map[string]json.RawMessage) {
	probeKV(w, "IP", data, "ip")
	probeKVList(w, "Reverse DNS", data, "reverse_dns")
	probeKV(w, "ASN", data, "asn")
	probeKV(w, "ASN Name", data, "asn_name")
	probeKV(w, "Org", data, "org")
	probeKV(w, "Country", data, "country")
	probeKV(w, "Prefix", data, "prefix")
}

func probePrintGeneric(w io.Writer, data map[string]json.RawMessage) {
	for k, v := range data {
		s := string(v)
		if len(s) > 80 {
			s = s[:77] + "..."
		}
		fmt.Fprintf(w, "  %-18s%s\n", k, s)
	}
}

// ── Probe output helpers ──

func probeKV(w io.Writer, label string, data map[string]json.RawMessage, key string) {
	if raw, ok := data[key]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			fmt.Fprintf(w, "  %-18s%s\n", label, s)
		}
	}
}

func probeKVInt(w io.Writer, label string, data map[string]json.RawMessage, key string) {
	if raw, ok := data[key]; ok {
		var n int
		if json.Unmarshal(raw, &n) == nil {
			fmt.Fprintf(w, "  %-18s%d\n", label, n)
		}
	}
}

func probeKVList(w io.Writer, label string, data map[string]json.RawMessage, key string) {
	if raw, ok := data[key]; ok {
		var items []string
		if json.Unmarshal(raw, &items) == nil && len(items) > 0 {
			fmt.Fprintf(w, "  %-14s%s\n", headerStyle.Render(label), items[0])
			for _, item := range items[1:] {
				fmt.Fprintf(w, "  %-14s%s\n", "", item)
			}
		}
	}
}

func probeJSONBool(data map[string]json.RawMessage, key string) bool {
	if raw, ok := data[key]; ok {
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			return b
		}
	}
	return false
}

// ProbeBatchReport renders batch probe results.
func ProbeBatchReport(w io.Writer, results []investigate.BatchResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\n",
		headerStyle.Render("TARGET"),
		headerStyle.Render("STATUS"),
		headerStyle.Render("MODULES"),
	)
	for _, br := range results {
		if br.Error != "" {
			fmt.Fprintf(tw, "%s\t%s\t%s\n",
				br.Target,
				critStyle.Render("FAILED"),
				truncate(br.Error, 60),
			)
		} else if br.Report != nil {
			fmt.Fprintf(tw, "%s\t%s\t%s\n",
				br.Target,
				greenStyle.Render("OK"),
				fmt.Sprintf("%d ok, %d failed", br.Report.Summary.ModulesOK, br.Report.Summary.ModulesFailed),
			)
		}
	}
	tw.Flush()
}

func probeScoreTable(w io.Writer, score *investigate.ScoreResult) {
	gradeStyle := critStyle
	switch score.Grade {
	case "A", "B":
		gradeStyle = greenStyle
	case "C":
		gradeStyle = medStyle
	case "D":
		gradeStyle = highStyle
	}
	fmt.Fprintf(w, "\n%s  %s  %d%%  (%d passed, %d failed)\n",
		headerStyle.Render("Security Score:"),
		gradeStyle.Render(score.Grade),
		score.Percentage,
		score.Passed,
		score.Failed,
	)

	// Category breakdown.
	categories := []struct{ key, label string }{
		{"transport", "Transport Security"},
		{"email", "Email Security"},
		{"certificate", "Certificate Health"},
		{"headers", "Security Headers"},
		{"infrastructure", "Infrastructure"},
		{"exposure", "Information Exposure"},
	}
	fmt.Fprintln(w)
	for _, cat := range categories {
		var catScore, catMax int
		for _, c := range score.Checks {
			if c.Category == cat.key {
				catMax += c.Max
				catScore += c.Points
			}
		}
		if catMax == 0 {
			continue
		}
		pct := catScore * 100 / catMax
		pctStyle := critStyle
		if pct >= 90 {
			pctStyle = greenStyle
		} else if pct >= 70 {
			pctStyle = medStyle
		}
		fmt.Fprintf(w, "  %-24s %s (%d/%d)\n",
			headerStyle.Render(cat.label),
			pctStyle.Render(fmt.Sprintf("%3d%%", pct)),
			catScore, catMax,
		)
	}

	// Individual checks.
	fmt.Fprintf(w, "\n  %s\n", headerStyle.Render("Checks"))
	for _, c := range score.Checks {
		if c.Pass {
			fmt.Fprintf(w, "  %s %-35s %d/%d\n", greenStyle.Render("✓"), c.Check, c.Points, c.Max)
		} else {
			fmt.Fprintf(w, "  %s %-35s %d/%d\n", critStyle.Render("✗"), c.Check, c.Points, c.Max)
		}
	}

	if len(score.Recommendations) > 0 {
		fmt.Fprintf(w, "\n  %s\n", headerStyle.Render("Recommendations"))
		for _, rec := range score.Recommendations {
			fmt.Fprintf(w, "  %s %s\n", medStyle.Render("→"), rec)
		}
	}
}

func truncate(s string, n int) string {
	if n < 4 || len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
