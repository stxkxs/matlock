package cmd

import (
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// exitCode is the process exit status returned by Execute. 0 means clean (or
// --fail-on was not set); 2 means at least one finding met or exceeded the
// --fail-on severity threshold. Exit code 1 is reserved for command errors and
// is set directly in Execute.
var exitCode int

// failOn holds the --fail-on severity threshold (CRITICAL/HIGH/MEDIUM/LOW).
// Empty means findings never affect the exit code.
var failOn string

// gate raises the exit code to 2 when --fail-on is set and any item's severity
// (extracted via sev) meets or exceeds the threshold. No-op when --fail-on is
// empty, so default behaviour is unchanged.
func gate[T any](items []T, sev func(T) cloud.Severity) {
	if failOn == "" {
		return
	}
	threshold := cloud.SeverityRank(cloud.Severity(strings.ToUpper(failOn)))
	for _, it := range items {
		if cloud.SeverityRank(sev(it)) >= threshold {
			exitCode = 2
			return
		}
	}
}

// gateBool raises the exit code to 2 when --fail-on is set and cond is true. For
// domains without a per-finding severity (e.g. drift), any qualifying finding
// trips the gate regardless of the threshold value.
func gateBool(cond bool) {
	if failOn != "" && cond {
		exitCode = 2
	}
}
