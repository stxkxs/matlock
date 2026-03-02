package gcp

import (
	"context"
	"os"

	"google.golang.org/api/option"
)

// Provider implements Matlock provider interfaces for GCP.
type Provider struct {
	projectID string
	opts      []option.ClientOption
}

// New creates a GCP provider using Application Default Credentials.
// projectID can be set explicitly; if empty it is read from GOOGLE_CLOUD_PROJECT.
func New(ctx context.Context, projectID string) (*Provider, error) {
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("GCLOUD_PROJECT")
		}
	}
	return &Provider{projectID: projectID}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "gcp" }

// Detect returns true when GCP credentials are present in the environment.
func (p *Provider) Detect(_ context.Context) bool {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		return true
	}
	if os.Getenv("GOOGLE_CLOUD_PROJECT") != "" || os.Getenv("GCLOUD_PROJECT") != "" {
		return true
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		adc := home + "/.config/gcloud/application_default_credentials.json"
		if _, err := os.Stat(adc); err == nil {
			return true
		}
	}
	return false
}
