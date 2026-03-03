package aws

import (
	"context"
	"os"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// Provider implements all Matlock provider interfaces for AWS.
type Provider struct {
	cfg awssdk.Config
}

// New loads credentials from the default chain and returns a Provider.
func New(ctx context.Context) (*Provider, error) {
	return NewWithProfile(ctx, "")
}

// NewWithProfile loads credentials using the named AWS profile. If profile is empty, the default chain is used.
func NewWithProfile(ctx context.Context, profile string) (*Provider, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRetryMaxAttempts(5),
		config.WithRetryMode(awssdk.RetryModeStandard),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "aws" }

// Detect returns true when AWS credentials are present in the environment.
func (p *Provider) Detect(ctx context.Context) bool {
	envKeys := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_PROFILE",
		"AWS_DEFAULT_REGION",
		"AWS_ROLE_ARN",
	}
	for _, k := range envKeys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		for _, f := range []string{"/.aws/credentials", "/.aws/config"} {
			if _, err := os.Stat(home + f); err == nil {
				return true
			}
		}
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return false
	}
	_, err = cfg.Credentials.Retrieve(ctx)
	return err == nil
}
