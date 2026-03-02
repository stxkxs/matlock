package output

import (
	"encoding/json"
	"io"

	"github.com/stxkxs/matlock/internal/cloud"
)

type iamReport struct {
	Findings        []cloud.Finding                `json:"findings"`
	Total           int                            `json:"total"`
	Principals      int                            `json:"principals_scanned"`
	UsedPermissions map[string][]cloud.Permission  `json:"used_permissions,omitempty"`
}

type storageReport struct {
	Findings []cloud.BucketFinding `json:"findings"`
	Total    int                   `json:"total"`
}

type orphansReport struct {
	Resources          []cloud.OrphanResource `json:"resources"`
	Total              int                    `json:"total"`
	EstimatedMonthlyUSD float64               `json:"estimated_monthly_usd"`
}

type costReport struct {
	Diffs []cloud.CostDiff `json:"diffs"`
}

// WriteIAM marshals IAM findings as JSON to w.
func WriteIAM(w io.Writer, findings []cloud.Finding, principalsScanned int, usedPerms map[string][]cloud.Permission) error {
	return writeJSON(w, iamReport{
		Findings:        findings,
		Total:           len(findings),
		Principals:      principalsScanned,
		UsedPermissions: usedPerms,
	})
}

// WriteStorage marshals storage findings as JSON to w.
func WriteStorage(w io.Writer, findings []cloud.BucketFinding) error {
	return writeJSON(w, storageReport{
		Findings: findings,
		Total:    len(findings),
	})
}

// WriteOrphans marshals orphan resources as JSON to w.
func WriteOrphans(w io.Writer, orphans []cloud.OrphanResource) error {
	var total float64
	for _, o := range orphans {
		total += o.MonthlyCost
	}
	return writeJSON(w, orphansReport{
		Resources:          orphans,
		Total:              len(orphans),
		EstimatedMonthlyUSD: total,
	})
}

// WriteCost marshals cost diffs as JSON to w.
func WriteCost(w io.Writer, diffs []cloud.CostDiff) error {
	return writeJSON(w, costReport{Diffs: diffs})
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
