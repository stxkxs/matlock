package azure

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/stxkxs/matlock/internal/cloud"
)

// ListCertificates discovers Azure Key Vault certificates expiring within 180 days.
func (p *Provider) ListCertificates(ctx context.Context) ([]cloud.CertFinding, error) {
	vaultClient, err := armkeyvault.NewVaultsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("keyvault vaults client: %w", err)
	}

	now := time.Now()
	var findings []cloud.CertFinding

	pager := vaultClient.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list key vaults: %w", err)
		}
		for _, vault := range page.Value {
			if vault.Properties == nil || vault.Properties.VaultURI == nil {
				continue
			}
			vaultURI := *vault.Properties.VaultURI
			vaultName := ptrStr(vault.Name)
			region := ptrStr(vault.Location)

			certFindings, err := p.listVaultCerts(ctx, vaultURI, vaultName, region, now)
			if err != nil {
				// Individual vault access errors are non-fatal — warn and continue
				fmt.Fprintf(os.Stderr, "warn: key vault %s: %v\n", vaultName, err)
				continue
			}
			findings = append(findings, certFindings...)
		}
	}
	return findings, nil
}

func (p *Provider) listVaultCerts(ctx context.Context, vaultURI, vaultName, region string, now time.Time) ([]cloud.CertFinding, error) {
	client, err := azcertificates.NewClient(vaultURI, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("certificates client: %w", err)
	}

	var findings []cloud.CertFinding
	pager := client.NewListCertificatePropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list certificates: %w", err)
		}
		for _, cert := range page.Value {
			if cert == nil || cert.Attributes == nil || cert.Attributes.Expires == nil {
				continue
			}
			expiry := *cert.Attributes.Expires
			daysLeft := int(math.Floor(expiry.Sub(now).Hours() / 24))
			if daysLeft > 180 {
				continue
			}

			certName := certNameFromID(string(*cert.ID))
			sev, status := cloud.CertSeverity(daysLeft)
			findings = append(findings, cloud.CertFinding{
				Severity:  sev,
				Status:    status,
				Provider:  "azure",
				Domain:    certName,
				ARN:       fmt.Sprintf("%s/certificates/%s", vaultName, certName),
				Region:    region,
				ExpiresAt: expiry,
				DaysLeft:  daysLeft,
				Detail:    fmt.Sprintf("certificate %s in vault %s expires in %d days", certName, vaultName, daysLeft),
			})
		}
	}
	return findings, nil
}

// certNameFromID extracts the certificate name from a Key Vault certificate ID URL.
// ID format: https://{vault}.vault.azure.net/certificates/{name}/{version}
func certNameFromID(id string) string {
	// Find "certificates/" segment
	const marker = "/certificates/"
	idx := -1
	for i := 0; i+len(marker) <= len(id); i++ {
		if id[i:i+len(marker)] == marker {
			idx = i + len(marker)
			break
		}
	}
	if idx < 0 {
		return id
	}
	rest := id[idx:]
	// Take everything up to the next slash (version)
	for i, c := range rest {
		if c == '/' {
			return rest[:i]
		}
	}
	return rest
}
