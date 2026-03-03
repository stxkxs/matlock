package cloud

import "context"

// Provider is the base interface every cloud backend must implement.
type Provider interface {
	Name() string
	// Detect returns true when credentials for this provider are available in the environment.
	Detect(ctx context.Context) bool
}

// PrincipalType identifies the kind of IAM principal.
type PrincipalType string

const (
	PrincipalUser            PrincipalType = "user"
	PrincipalRole            PrincipalType = "role"             // AWS
	PrincipalServiceAccount  PrincipalType = "service_account"  // GCP
	PrincipalManagedIdentity PrincipalType = "managed_identity" // Azure
)

// Principal represents an IAM identity on any cloud.
type Principal struct {
	ID       string
	Name     string
	Type     PrincipalType
	Provider string
	Metadata map[string]string
}

// Permission is a single privilege that was granted to or used by a principal.
type Permission struct {
	Action   string  // "s3:GetObject" / "storage.objects.get" / "Microsoft.Storage/..."
	Resource string  // ARN / resource path / scope
	LastUsed *string // ISO-8601 timestamp from audit logs; nil if never used
}

// Policy is a minimal policy document ready for rendering.
type Policy struct {
	Provider string // "aws" | "gcp" | "azure"
	Format   string // "aws-iam-json" | "gcp-custom-role" | "azure-custom-role"
	Raw      []byte
}

// Severity of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// SeverityRank returns a numeric rank for ordering (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// FindingType classifies what was detected.
type FindingType string

const (
	FindingAdminAccess        FindingType = "ADMIN_ACCESS"
	FindingWildcardResource   FindingType = "WILDCARD_RESOURCE"
	FindingUnusedPermission   FindingType = "UNUSED_PERMISSION"
	FindingCrossAccountAccess FindingType = "CROSS_ACCOUNT_ACCESS"
	FindingStalePrincipal     FindingType = "STALE_PRINCIPAL"
	FindingBroadScope         FindingType = "BROAD_SCOPE"
	FindingPublicAccess       FindingType = "PUBLIC_ACCESS"
	FindingUnencrypted        FindingType = "UNENCRYPTED"
	FindingNoVersioning       FindingType = "NO_VERSIONING"
	FindingOrphanResource     FindingType = "ORPHAN_RESOURCE"
)

// Finding is a single security, cost, or hygiene observation.
type Finding struct {
	Severity    Severity
	Type        FindingType
	Provider    string
	Principal   *Principal // nil for non-IAM findings
	Resource    string
	Detail      string
	Remediation string
}
