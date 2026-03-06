package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/secrets"
)

// ScanSecrets checks App Service settings and Function App settings for secrets.
func (p *Provider) ScanSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	if f, err := p.scanWebAppSecrets(ctx); err != nil {
		return nil, fmt.Errorf("web app secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	return findings, nil
}

func (p *Provider) scanWebAppSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	client, err := armappservice.NewWebAppsClient(p.subscriptionID, p.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create web apps client: %w", err)
	}

	var findings []cloud.SecretFinding
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("list web apps: %w", err)
		}
		for _, app := range page.Value {
			if app.Name == nil {
				continue
			}
			appName := *app.Name
			rg := resourceGroupFromID(app.ID)
			if rg == "" {
				continue
			}

			resourceType := "app_service_setting"
			resourcePrefix := "app-service:"
			if app.Kind != nil && (strings.Contains(*app.Kind, "functionapp")) {
				resourceType = "function_app_setting"
				resourcePrefix = "function-app:"
			}

			settingsResp, err := client.ListApplicationSettings(ctx, rg, appName, nil)
			if err != nil {
				continue
			}
			if settingsResp.Properties == nil {
				continue
			}
			location := ""
			if app.Location != nil {
				location = *app.Location
			}
			for key, val := range settingsResp.Properties {
				if val == nil {
					continue
				}
				for _, m := range secrets.Scan(*val) {
					findings = append(findings, cloud.SecretFinding{
						Severity:     m.Severity,
						Type:         m.Type,
						Provider:     "azure",
						Resource:     resourcePrefix + appName,
						ResourceType: resourceType,
						Region:       location,
						Key:          key,
						Match:        secrets.Redact(m.Value),
						Detail:       fmt.Sprintf("%s found in %s%s setting %q", m.Name, resourcePrefix, appName, key),
						Remediation:  fmt.Sprintf("Move secret from app setting %q to Key Vault and use Key Vault reference", key),
					})
				}
			}
		}
	}
	return findings, nil
}

func resourceGroupFromID(id *string) string {
	if id == nil {
		return ""
	}
	parts := strings.Split(*id, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
