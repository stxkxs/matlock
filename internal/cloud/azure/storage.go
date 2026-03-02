package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stxkxs/matlock/internal/cloud"
)

// AuditStorage checks Azure Blob storage accounts for security misconfigurations.
func (p *Provider) AuditStorage(ctx context.Context) ([]cloud.BucketFinding, error) {
	client, err := armstorage.NewAccountsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("storage accounts client: %w", err)
	}

	var findings []cloud.BucketFinding
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list storage accounts: %w", err)
		}
		for _, acct := range page.Value {
			if acct.Properties == nil {
				continue
			}
			name := ptrStr(acct.Name)
			region := ptrStr(acct.Location)

			findings = append(findings, p.checkAzurePublicAccess(acct, name, region)...)
			findings = append(findings, p.checkAzureEncryption(acct, name, region)...)
			findings = append(findings, p.checkAzureHTTPS(acct, name, region)...)
		}
	}
	return findings, nil
}

func (p *Provider) checkAzurePublicAccess(acct *armstorage.Account, name, region string) []cloud.BucketFinding {
	if acct.Properties.AllowBlobPublicAccess != nil && *acct.Properties.AllowBlobPublicAccess {
		return []cloud.BucketFinding{{
			Severity:    cloud.SeverityCritical,
			Type:        cloud.BucketPublicAccess,
			Provider:    "azure",
			Bucket:      name,
			Region:      region,
			Detail:      "blob public access is allowed",
			Remediation: fmt.Sprintf("az storage account update --name %s --allow-blob-public-access false", name),
		}}
	}
	return nil
}

func (p *Provider) checkAzureEncryption(acct *armstorage.Account, name, region string) []cloud.BucketFinding {
	if acct.Properties.Encryption == nil {
		return []cloud.BucketFinding{{
			Severity:    cloud.SeverityHigh,
			Type:        cloud.BucketUnencrypted,
			Provider:    "azure",
			Bucket:      name,
			Region:      region,
			Detail:      "encryption configuration is missing",
			Remediation: fmt.Sprintf("az storage account update --name %s --encryption-services blob", name),
		}}
	}
	return nil
}

func (p *Provider) checkAzureHTTPS(acct *armstorage.Account, name, region string) []cloud.BucketFinding {
	if acct.Properties.EnableHTTPSTrafficOnly != nil && !*acct.Properties.EnableHTTPSTrafficOnly {
		return []cloud.BucketFinding{{
			Severity:    cloud.SeverityHigh,
			Type:        cloud.BucketPublicAccess,
			Provider:    "azure",
			Bucket:      name,
			Region:      region,
			Detail:      "HTTP traffic is allowed (HTTPS-only is not enforced)",
			Remediation: fmt.Sprintf("az storage account update --name %s --https-only true", name),
		}}
	}
	return nil
}
