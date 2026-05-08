package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// FilterConfig defines a query filter that can be declared in the config file.
// Operator defaults to "=" if omitted.
type FilterConfig struct {
	Name     string `yaml:"name"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

// SecurityCenter holds connection credentials and optional per-instance filters.
type SecurityCenter struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	// SkipTLS disables certificate verification (use only in lab environments).
	SkipTLS bool `yaml:"skip_tls"`
	// Filters are extra query filters applied only when querying this SC.
	// They are merged with DefaultFilters and appended before CLI filters.
	Filters []FilterConfig `yaml:"filters"`
}

// Config is the top-level configuration loaded from the YAML file.
type Config struct {
	SecurityCenters []SecurityCenter `yaml:"security_centers"`
	// DefaultFilters are applied to every query, for every SC, before CLI filters.
	// Ignored when --filter-mode override is used.
	DefaultFilters []FilterConfig `yaml:"default_filters"`
	// DefaultColumns is the list of SC field names to request and display when
	// --columns is not passed on the command line.  Each entry is a single field
	// name (e.g. "ip", "pluginID").  Takes precedence over the built-in fallback.
	DefaultColumns []string `yaml:"default_columns"`
	// LogLevel controls verbosity: debug, info, warn, error.
	LogLevel string `yaml:"log_level"`
	// LogFile is the path for a structured JSON log file. Empty = file logging disabled.
	LogFile string `yaml:"log_file"`
	// PageSize is the number of records fetched per API page (default 1000).
	PageSize int `yaml:"page_size"`
	// Timeout is the HTTP request timeout in seconds (default 300).
	// Increase this when querying large repositories or slow SC instances.
	Timeout int `yaml:"timeout"`
	// SearchKeywords is the list of substrings searched case-insensitively
	// against the pluginText field when running in full-search mode (--search-output).
	SearchKeywords []string `yaml:"search_keywords"`
	// SearchOutput is the default CSV output path for full-search mode.
	// Can be overridden at runtime with --search-output.
	SearchOutput string `yaml:"search_output"`
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
	if cfg.Timeout <= 0 {
		cfg.Timeout = 300
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	// Default operator for any filter that omits it.
	for i := range cfg.DefaultFilters {
		if cfg.DefaultFilters[i].Operator == "" {
			cfg.DefaultFilters[i].Operator = "="
		}
	}
	for si := range cfg.SecurityCenters {
		for i := range cfg.SecurityCenters[si].Filters {
			if cfg.SecurityCenters[si].Filters[i].Operator == "" {
				cfg.SecurityCenters[si].Filters[i].Operator = "="
			}
		}
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
