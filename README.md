# matlock

Multi-cloud security and cost swiss army knife — single binary, zero dependencies.

Audit IAM permissions, spot cost anomalies, find orphaned resources, flag insecure storage, detect overly permissive firewall rules, monitor TLS certificate expiry, and enforce resource tagging across AWS, GCP, and Azure.

<!-- screenshot placeholder -->
<!-- ![matlock iam scan output](docs/screenshots/iam-scan.png) -->

---

## Installation

### Homebrew (macOS / Linux)

```sh
brew install stxkxs/tap/matlock
```

### go install

```sh
go install github.com/stxkxs/matlock@latest
```

### Direct download

Pre-built binaries for Linux, macOS, and Windows are attached to every [GitHub release](https://github.com/stxkxs/matlock/releases).

```sh
# macOS arm64 example
curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/matlock_Darwin_arm64.tar.gz \
  | tar -xz matlock
sudo mv matlock /usr/local/bin/
```

Verify the download against the published SHA256 checksums:

```sh
curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/checksums.txt | sha256sum --check --ignore-missing
```

### Build from source

Requires Go 1.26+ and [Task](https://taskfile.dev).

```sh
git clone https://github.com/stxkxs/matlock.git
cd matlock
task build
```

---

## Credentials setup

matlock auto-detects available providers from environment variables and credential files. You only need to configure the providers you actually use.

### AWS

matlock uses the standard AWS SDK credential chain.

```sh
# Option 1 — environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1

# Option 2 — named profile
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1

# Option 3 — IAM role / instance metadata (no env vars needed)
```

Required IAM permissions for a read-only audit role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "cloudtrail:LookupEvents",
        "ce:GetCostAndUsage",
        "ec2:Describe*",
        "elasticloadbalancing:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "rds:DescribeDBInstances",
        "lambda:ListFunctions",
        "lambda:ListTags"
      ],
      "Resource": "*"
    }
  ]
}
```

### GCP

```sh
# Option 1 — application default credentials (gcloud)
gcloud auth application-default login

# Option 2 — service account key
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
export GOOGLE_CLOUD_PROJECT=my-project-id

# Required for cost diff
export GOOGLE_BILLING_ACCOUNT_ID=XXXXXX-XXXXXX-XXXXXX
```

Required IAM roles for the service account:
- `roles/iam.securityReviewer`
- `roles/logging.viewer`
- `roles/billing.viewer`
- `roles/storage.objectViewer`
- `roles/compute.viewer`
- `roles/certificatemanager.viewer` (for `matlock certs`)

### Azure

```sh
# Option 1 — Azure CLI
az login
export AZURE_SUBSCRIPTION_ID=...

# Option 2 — service principal
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...
```

Required role assignments:
- `Reader` on the subscription
- `Cost Management Reader` on the subscription
- `Key Vault Reader` + `Key Vault Certificates Officer` (or `Key Vault Reader` if using RBAC-enabled vaults) for `matlock certs`

---

## Commands

### `matlock iam scan` — unused and overprivileged IAM

Compares granted permissions against CloudTrail / Audit Log activity over the lookback window and reports unused, admin, and cross-account risks.

```sh
# Scan all auto-detected providers (90-day lookback)
matlock iam scan

# AWS only, last 30 days, show CRITICAL and HIGH only
matlock iam scan --provider aws --days 30 --severity HIGH

# Scan a specific principal
matlock iam scan --provider gcp --principal serviceAccount:scanner@my-project.iam.gserviceaccount.com

# JSON output for downstream tooling
matlock iam scan --output json --output-file report.json

# SARIF output for GitHub Advanced Security
matlock iam scan --output sarif --output-file results.sarif

# Increase parallelism for large accounts
matlock iam scan --concurrency 20
```

<!-- screenshot placeholder -->
<!-- ![iam scan table output](docs/screenshots/iam-scan.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan: `aws`, `gcp`, `azure` |
| `--days` | `90` | Audit log lookback window in days |
| `--principal` | | Scan a single principal by name or ID |
| `--severity` | `LOW` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--output` | `table` | Output format: `table`, `json`, `sarif` |
| `--output-file` | | Write output to file instead of stdout |
| `--concurrency` | `10` | Maximum parallel goroutines per provider |
| `--profile` | | AWS named profile to use for credentials |

---

### `matlock iam fix` — generate Terraform remediations

Reads a JSON scan report and generates least-privilege Terraform policy files for each flagged principal.

```sh
# Generate fixes for all HIGH+ findings
matlock iam fix --from report.json

# Write fixes to a custom directory
matlock iam fix --from report.json --out ./tf-fixes

# Include MEDIUM severity fixes too
matlock iam fix --from report.json --severity MEDIUM
```

**Workflow**

```sh
matlock iam scan --output json --output-file report.json
matlock iam fix --from report.json --out ./fixes
ls ./fixes/
# minimal_lambda_executor.tf
# minimal_my_project_scanner_at_my_project_iam_gserviceaccount_com.tf
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--from` | (required) | Path to JSON report from `matlock iam scan --output json` |
| `--format` | `terraform` | Output format: `terraform`, `json` |
| `--out` | `./matlock-fixes` | Output directory for generated files |
| `--severity` | `HIGH` | Minimum severity to generate fixes for |

---

### `matlock cost diff` — spend delta between time windows

Compares cloud spend between the last N days and the N days before that, surfacing unexpected increases service by service.

```sh
# Compare last 30 days vs the 30 days before
matlock cost diff

# 7-day comparison, AWS only
matlock cost diff --provider aws --days 7

# JSON output for alerting pipelines
matlock cost diff --output json
```

<!-- screenshot placeholder -->
<!-- ![cost diff table output](docs/screenshots/cost-diff.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to query |
| `--days` | `30` | Compare last N days vs N days before |
| `--threshold` | `0` | Only show services with >N% change (e.g. `--threshold 20`) |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

Cost increases >10% are shown in red; decreases are shown in green.

---

### `matlock orphans` — unused disks, IPs, and load balancers

Finds unattached disks, reserved IPs with no instance, and idle load balancers. Reports estimated monthly cost.

```sh
# All providers
matlock orphans

# Only report resources costing more than $5/month
matlock orphans --min-cost 5

# JSON for Slack/PagerDuty integration
matlock orphans --output json
```

<!-- screenshot placeholder -->
<!-- ![orphans table output](docs/screenshots/orphans.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--min-cost` | `0` | Only report orphans with monthly cost above this USD threshold |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

The table includes a TOTAL row summing all monthly costs.

---

### `matlock storage audit` — public buckets and encryption gaps

Audits object storage for public access, missing encryption, disabled versioning, and missing access logging.

```sh
# All providers
matlock storage audit

# HIGH and CRITICAL findings only
matlock storage audit --severity HIGH

# JSON for SIEM ingestion
matlock storage audit --output json --output-file storage-findings.json
```

<!-- screenshot placeholder -->
<!-- ![storage audit table output](docs/screenshots/storage-audit.png) -->

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock network audit` — overly permissive firewall rules

Checks security groups (AWS), firewall rules (GCP), and network security groups (Azure) for rules that expose sensitive ports to the internet.

Severity rules:
- **CRITICAL** — `0.0.0.0/0` on SSH (22), RDP (3389), or database ports (3306, 5432, 1433, 27017, 6379, 9200)
- **HIGH** — `0.0.0.0/0` on any non-HTTP/HTTPS port
- **MEDIUM** — unrestricted egress (all traffic to `0.0.0.0/0`)

```sh
# All providers
matlock network audit

# AWS only, show CRITICAL findings
matlock network audit --provider aws --severity CRITICAL

# JSON output
matlock network audit --output json --output-file network-findings.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

### `matlock certs` — TLS certificate expiry

Lists TLS certificates from ACM (AWS), Certificate Manager (GCP), and Azure Key Vault that are expired or expiring soon.

Severity rules:
- **CRITICAL** — expired, or expiring within 7 days
- **HIGH** — expiring within 30 days
- **MEDIUM** — expiring within 60 days
- **LOW** — expiring within 90 days (default `--days` threshold)

```sh
# All providers, warn on certs expiring within 90 days (default)
matlock certs

# Only show certs expiring within 30 days
matlock certs --days 30

# AWS only, CRITICAL and HIGH only
matlock certs --provider aws --severity HIGH

# JSON output
matlock certs --output json --output-file certs.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--days` | `90` | Include certs expiring within this many days |
| `--severity` | `LOW` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

> **GCP note:** Certificate Manager must be enabled in your project (`gcloud services enable certificatemanager.googleapis.com`). If the API is not enabled, `matlock certs` skips GCP with a warning.

---

### `matlock tags` — missing resource tags/labels

Audits EC2 instances, S3 buckets, RDS databases, Lambda functions (AWS), compute instances and GCS buckets (GCP), and all resource types (Azure) for missing required tags or labels.

All findings are **MEDIUM** severity.

```sh
# Require owner, env, and cost-center tags across all providers
matlock tags --require owner,env,cost-center

# AWS only
matlock tags --provider aws --require owner,env

# JSON output
matlock tags --require owner,env --output json --output-file tags.json
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | auto | Cloud providers to scan |
| `--require` | (required) | Comma-separated tag/label keys that must be present |
| `--severity` | `MEDIUM` | Minimum severity to report |
| `--output` | `table` | Output format: `table`, `json` |
| `--output-file` | | Write output to file instead of stdout |

---

## Global flags

| Flag | Description |
|------|-------------|
| `--quiet`, `-q` | Suppress all progress and summary output on stderr (for scripts) |
| `--version` | Print version, commit hash, and build date |

---

## CI usage

### GitHub Actions — SARIF upload

Upload IAM findings to GitHub Advanced Security (requires `security-events: write` permission):

```yaml
name: matlock security scan

on:
  schedule:
    - cron: '0 6 * * 1'   # every Monday at 06:00 UTC
  workflow_dispatch:

permissions:
  security-events: write

jobs:
  iam-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install matlock
        run: |
          curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/matlock_Linux_amd64.tar.gz \
            | tar -xz matlock
          sudo mv matlock /usr/local/bin/

      - name: Run IAM scan
        env:
          AWS_ROLE_ARN: ${{ secrets.MATLOCK_ROLE_ARN }}
          AWS_REGION: us-east-1
        run: |
          matlock iam scan \
            --provider aws \
            --severity HIGH \
            --output sarif \
            --output-file results.sarif \
            --quiet

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI — JSON report artifact

```yaml
matlock:
  image: ubuntu:24.04
  before_script:
    - curl -sSL https://github.com/stxkxs/matlock/releases/latest/download/matlock_Linux_amd64.tar.gz
        | tar -xz matlock
    - mv matlock /usr/local/bin/
  script:
    - matlock iam scan --output json --output-file report.json --quiet
    - matlock storage audit --severity HIGH --output json --output-file storage.json --quiet
  artifacts:
    paths:
      - report.json
      - storage.json
    expire_in: 30 days
```

### Fail CI on critical findings

```sh
# Exit non-zero if any CRITICAL findings exist
matlock iam scan --severity CRITICAL --output json --quiet | \
  jq -e '.findings | length == 0'
```

---

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Table | `--output table` | Human-readable terminal output with colors |
| JSON | `--output json` | Scripts, alerting, dashboards |
| SARIF | `--output sarif` | GitHub Advanced Security, IDE integrations |

All formats can be written to a file with `--output-file path/to/file`.

---

## Version

```sh
matlock --version
# v0.1.0 (commit abc1234, built 2026-03-01T12:00:00Z)
```

---

## License

MIT — see [LICENSE](LICENSE).
