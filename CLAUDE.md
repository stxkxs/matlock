# matlock — development brief

Multi-cloud security and cost swiss army knife CLI. Written in Go 1.26.
Module: `github.com/stxkxs/matlock`
Build: `task build`

## project goal

Production-quality open-source CLI for public release on GitHub.
Target users: platform engineers, security engineers, DevOps teams.
Differentiator: single binary, multi-cloud (aws/gcp/azure), four distinct domains.

## commands

- `matlock iam scan` — unused/overprivileged IAM permissions vs CloudTrail/Audit Logs
- `matlock iam fix` — generate Terraform fix files from scan report
- `matlock cost diff` — spend delta between two time windows
- `matlock orphans` — unused disks, IPs, load balancers
- `matlock storage audit` — public buckets, unencrypted storage, versioning, logging

## code conventions

- Idiomatic Go. No magic. Keep packages small and focused.
- Errors: wrap with `fmt.Errorf("context: %w", err)`. Never swallow.
- All cloud API calls must be context-aware.
- Table output via lipgloss + tabwriter. No bubbletea (no interactive TUI needed).
- No global state. No init() side effects beyond cobra command registration.
- `task build` must always pass before marking any backlog item complete.
- `go test ./...` must always pass (no failing tests).

## import aliases (use these consistently)

```go
awssdk   "github.com/aws/aws-sdk-go-v2/aws"
cloudaws "github.com/stxkxs/matlock/internal/cloud/aws"
cloudgcp "github.com/stxkxs/matlock/internal/cloud/gcp"
cloudazure "github.com/stxkxs/matlock/internal/cloud/azure"
orphanscanner "github.com/stxkxs/matlock/internal/orphans"
```

## guardrails — do not do these

- Do not refactor, rename, or clean up code that is not directly required by the current backlog item.
- Do not add new external dependencies unless the backlog item explicitly requires one and nothing in stdlib or existing deps works.
- Do not change any public interface (Provider, IAMProvider, CostProvider, etc.) without updating every implementation and every call site.
- Do not add comments or docstrings to functions you didn't modify.
- Do not add features, flags, or options that aren't in the current backlog item, even if they seem useful.
- Do not split one backlog item into multiple commits or partial implementations. Each item must be complete and working before marking [x].
- Do not mark an item [x] if `task build` or `go test ./...` fails.

## what "done" means for a backlog item

1. The feature/fix/file described in the item is fully implemented.
2. `task build` exits 0.
3. `go test ./...` exits 0 with no skipped tests related to the item.
4. No regressions in packages not mentioned in the backlog item.

## recovery — if the build breaks mid-pass

1. Read the error output carefully.
2. Fix only what the error points to — do not rewrite the surrounding code.
3. If a dependency or type doesn't exist, check the actual module in `~/go/pkg/mod` before guessing alternatives.
4. If stuck after two fix attempts, revert the failing file to its last working state and add a note to the backlog item instead of marking it [x].

## mock pattern for tests

All tests must run with `go test ./...` and no cloud credentials. Use interface mocks:

```go
// implement only the methods needed for the test
type mockOrphansProvider struct {
    orphans []cloud.OrphanResource
    err     error
}
func (m *mockOrphansProvider) Name() string { return "mock" }
func (m *mockOrphansProvider) Detect(_ context.Context) bool { return true }
func (m *mockOrphansProvider) ListOrphans(_ context.Context) ([]cloud.OrphanResource, error) {
    return m.orphans, m.err
}
```

Do not use `gomock`, `testify/mock`, or any mock-generation library. Hand-written mocks only.

## known bugs in the current code

- `internal/cloud/aws/iam.go` line ~200: `var _ iamtypes.AttachedPolicy` is a leftover import-satisfaction hack. Remove it and clean up the unused `iamtypes` import when touching that file.
- `cmd/iam.go` `runIAMFix`: calls `MinimalPolicy(ctx, principal, nil)` — passing nil for used permissions means every generated policy will be empty. The fix is described in section 2 of the backlog.
- `internal/cloud/gcp/auditlogs.go` `extractMethod`: only handles `map[string]interface{}` but the Cloud Logging SDK returns `*structpb.Struct`. Currently returns empty string for all real log entries.

## backlog

Work through these in order. Mark items `[x]` when done.
When all items in a section are done, move to the next section.

### section 1 — tests (required for public release)

- [x] `internal/iam/analyzer_test.go` — unit tests for `analyze()`: admin action detection, wildcard resource, unused permission, stale principal, cross-account, dedup. Use table-driven tests with mock principals and permissions.
- [x] `internal/iam/suggest_test.go` — test `BuildMinimalPermissions` and `GroupByResource`
- [x] `internal/fix/terraform_test.go` — test `formatAWSTF`, `formatGCPTF`, `slug`, `extractGCPPermissions`
- [x] `internal/output/json_test.go` — test JSON marshaling round-trips for all report types
- [x] `internal/orphans/scanner_test.go` — test `Scan` with a mock provider, `TotalMonthlyCost`
- [x] `internal/storage/scanner_test.go` — test `Scan` with a mock provider, severity filtering

### section 2 — robustness

- [x] Add concurrency to `iam.Scan`: scan principals in parallel with `errgroup`, cap goroutines at 10. Add `--concurrency` flag to `iam scan`.
- [x] Add exponential backoff retry wrapper for all AWS API calls (use `aws-sdk-go-v2`'s built-in retry with `RetryMaxAttempts: 5`).
- [x] Handle AWS paginator errors gracefully — log warning and continue rather than aborting the whole scan.
- [x] `internal/cloud/aws/iam.go`: handle `NoSuchEntity` errors when fetching individual policy versions (policy may have been deleted between list and get).
- [x] `internal/cloud/gcp/auditlogs.go`: `extractMethod` currently only handles `map[string]interface{}` — add handling for `*structpb.Struct` payload type from the logging SDK.
- [x] `cmd/iam.go` `runIAMFix`: currently generates empty policies. Fix: load used permissions from the scan report JSON (not by re-querying the API) and pass them to `MinimalPolicy`.

### section 3 — user experience

- [x] Add `--version` output that includes build date and git commit hash (already have Version ldflags, add `BuildDate` and `Commit` vars, set in Taskfile).
- [x] Add progress output to stderr during long scans: "scanning aws: 12/47 principals..." using a simple counter, not a spinner.
- [x] `matlock iam scan` table output: add a summary line at the bottom: "X critical, Y high, Z medium across N principals".
- [x] `matlock orphans` table: add a TOTAL row at the bottom showing sum of monthly cost.
- [x] Add `--quiet` flag to root command that suppresses all stderr progress/summary output (for use in scripts).
- [x] Color-code the cost diff table: red for cost increases >10%, green for decreases.

### section 4 — distribution

- [x] Write `.goreleaser.yaml`: build for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64. Include checksums. Use ldflags for version/commit/date.
- [x] Write `.github/workflows/release.yml`: trigger on tag push `v*`, run goreleaser.
- [x] Write `.github/workflows/ci.yml`: on push/PR — `go build ./...`, `go test ./...`, `go vet ./...`.
- [x] Write `README.md`: installation (brew tap + go install + direct download), quickstart for each command, credentials setup for each provider, CI usage example (SARIF output), screenshot placeholder.
- [x] Write `CONTRIBUTING.md`: how to add a new provider, how to add a new command group, test requirements.

### section 5 — completeness

- [x] `matlock iam scan --output sarif`: currently only works for IAM findings. Route storage findings through SARIF too (add `WriteStorageSARIF` to output package).
- [x] Add `matlock storage audit --fix`: generate remediation scripts (shell, not Terraform) for each finding. Write to `--out` directory.
- [x] Add `matlock cost diff --threshold 20` flag: only show services with >20% change.
- [x] `internal/cloud/gcp/cost.go`: implement using the Cloud Billing Budget API or BigQuery export. Add a note in the error if `GOOGLE_BILLING_ACCOUNT_ID` env var is not set.
- [x] Add `--profile` flag to `iam scan` for AWS named profiles (pass through to `config.LoadDefaultConfig` with `config.WithSharedConfigProfile`).

## how to run a single improvement pass (headless)

```bash
claude --print "Read CLAUDE.md. Find the first unchecked [ ] backlog item. Implement it fully. Mark it [x] when done. Run task build to verify it compiles. Run go test ./... to verify tests pass."
```

## release checklist

Before tagging v1.0.0:
- All section 1-4 backlog items marked [x]
- `task build` passes
- `go test ./...` passes with >80% coverage on analyzer package
- README has real screenshots
- goreleaser dry-run succeeds (`goreleaser release --snapshot --clean`)
