package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SecurityCenter holds connection credentials for one Tenable SC instance.
type SecurityCenter struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	// SkipTLS disables certificate verification (use only in lab environments).
	SkipTLS bool `yaml:"skip_tls"`
}

// Config is the top-level configuration loaded from the YAML file.
type Config struct {
	SecurityCenters []SecurityCenter `yaml:"security_centers"`
	// LogLevel controls verbosity: debug, info, warn, error.
	LogLevel string `yaml:"log_level"`
	// PageSize is the number of records fetched per API page (default 1000).
	PageSize int `yaml:"page_size"`
}

// Load reads and validates the YAML config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	// Apply defaults.
	if cfg.PageSize <= 0 {
		cfg.PageSize = 1000
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	// Validate.
	if len(cfg.SecurityCenters) == 0 {
		return nil, fmt.Errorf("config %q: no security_centers defined", path)
	}
	for i, sc := range cfg.SecurityCenters {
		if sc.URL == "" {
			return nil, fmt.Errorf("security_centers[%d]: missing url", i)
		}
		if sc.AccessKey == "" {
			return nil, fmt.Errorf("security_centers[%d] %q: missing access_key", i, sc.Name)
		}
		if sc.SecretKey == "" {
			return nil, fmt.Errorf("security_centers[%d] %q: missing secret_key", i, sc.Name)
		}
	}

	return &cfg, nil
}
