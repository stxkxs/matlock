package config

import (
	"github.com/spf13/viper"
)

// Config holds the values loaded from .matlock.yaml and environment.
type Config struct {
	DefaultProviders []string `mapstructure:"providers"`
	DefaultDays      int      `mapstructure:"days"`
	AWS              AWSConfig  `mapstructure:"aws"`
	GCP              GCPConfig  `mapstructure:"gcp"`
	Azure            AzureConfig `mapstructure:"azure"`
}

type AWSConfig struct {
	Region  string `mapstructure:"region"`
	Profile string `mapstructure:"profile"`
}

type GCPConfig struct {
	Project string `mapstructure:"project"`
}

type AzureConfig struct {
	SubscriptionID string `mapstructure:"subscription_id"`
}

// Load reads .matlock.yaml from the current directory or home directory.
func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigName(".matlock")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME")
	v.SetEnvPrefix("MATLOCK")
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("days", 90)
	v.SetDefault("providers", []string{})

	if err := v.ReadInConfig(); err != nil {
		// Config file is optional
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
