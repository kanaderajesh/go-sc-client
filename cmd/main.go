// sc-vuln is a command-line tool for fetching vulnerability data from one or
// more Tenable Security Center instances via the analysis REST API.
//
// Each requested severity level is processed in a separate goroutine so
// multiple severity × SC combinations run concurrently for maximum throughput.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kanaderajesh/go-sc-client/internal/client"
	"github.com/kanaderajesh/go-sc-client/internal/config"
	"github.com/kanaderajesh/go-sc-client/internal/output"
	"github.com/kanaderajesh/go-sc-client/internal/vuln"
)

// defaultColumns are returned when the user does not specify --columns.
var defaultColumns = []string{
	"_sc", "ip", "dnsName", "pluginID", "severity",
	"name", "protocol", "port", "firstSeen", "lastSeen",
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		cfgFile     string
		pluginText  string
		severities  string
		filterMode  string
		extraFilter []string
		columns     string
		format      string
		logLevel    string
		scNames     string
	)

	cmd := &cobra.Command{
		Use:   "sc-vuln",
		Short: "Fetch vulnerability data from Tenable Security Center",
		Long: `sc-vuln queries the Tenable Security Center /rest/analysis API for
vulnerability data. Each severity level runs in its own goroutine so that
requests to the same (or multiple) Security Centers are processed concurrently.

Authentication uses Tenable SC API keys (access_key + secret_key).

Example config (config.yaml):

  security_centers:
    - name: primary
      url: https://sc.example.com
      access_key: AAAA...
      secret_key: BBBB...
  log_level: info
  page_size: 1000

Usage examples:

  # Fetch critical and high vulns containing "apache" in plugin text
  sc-vuln --plugin-text apache --severity 4,3

  # Override all filters and return JSON
  sc-vuln --filter ip=10.0.0.1 --filter-mode override --format json

  # Custom columns, CSV output
  sc-vuln --columns ip,pluginID,name,cvssV3BaseScore --format csv
`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Build logger early so we can log config errors.
			log := newLogger(logLevel)

			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}

			// Config log level is a fallback when --log-level is not set.
			if logLevel == "" {
				log = newLogger(cfg.LogLevel)
			}

			// Optionally restrict which SCs are queried.
			if scNames != "" {
				cfg, err = filterSCs(cfg, scNames)
				if err != nil {
					return err
				}
			}

			sevList, err := parseSeverities(severities)
			if err != nil {
				return fmt.Errorf("--severity: %w", err)
			}

			extra, err := parseExtraFilters(extraFilter)
			if err != nil {
				return fmt.Errorf("--filter: %w", err)
			}

			cols := parseColumns(columns)

			opts := &vuln.Options{
				Severities:   sevList,
				PluginText:   pluginText,
				ExtraFilters: extra,
				FilterMode:   filterMode,
				Columns:      cols,
			}

			log.Info("starting",
				"security_centers", len(cfg.SecurityCenters),
				"severities", severityLabels(sevList),
				"pluginText", pluginText,
				"filterMode", filterMode,
				"format", format,
			)

			results := vuln.FetchAll(cfg, opts, log)
			rows, errs := vuln.Flatten(results)

			for _, e := range errs {
				log.Error("partial failure", "error", e)
			}

			log.Info("done", "total_records", len(rows))

			// Fall back to default columns when none were explicitly requested.
			displayCols := cols
			if len(displayCols) == 0 {
				displayCols = defaultColumns
			}

			return output.Format(os.Stdout, rows, displayCols, format)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&cfgFile, "config", "c", "config.yaml",
		"path to the YAML config file")
	f.StringVarP(&pluginText, "plugin-text", "p", "",
		"filter by plugin text (substring match against plugin output)")
	f.StringVarP(&severities, "severity", "s", "4,3,2,1,0",
		"comma-separated severity levels to query\n  0=Info  1=Low  2=Medium  3=High  4=Critical")
	f.StringVarP(&filterMode, "filter-mode", "m", "append",
		"how --filter values interact with built-in filters:\n  append   add to severity/pluginText defaults\n  override replace all defaults (severity is always kept)")
	f.StringArrayVarP(&extraFilter, "filter", "f", nil,
		"extra API filter as name=value (repeatable)\n  e.g. -f ip=10.0.0.1 -f repository=42")
	f.StringVar(&columns, "columns", "",
		"comma-separated SC field names to return\n  defaults: "+strings.Join(defaultColumns, ","))
	f.StringVarP(&format, "format", "o", "table",
		"output format: table | json | csv")
	f.StringVarP(&logLevel, "log-level", "l", "",
		"log verbosity: debug | info | warn | error\n  (overrides config file log_level)")
	f.StringVar(&scNames, "sc", "",
		"comma-separated SC names to query (default: all configured)")

	return cmd
}

// parseSeverities converts "4,3,2" → []int{4,3,2}, deduplicating and
// validating that each value is in the range [0,4].
func parseSeverities(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 4 {
			return nil, fmt.Errorf("invalid severity %q: must be an integer 0–4", p)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one severity must be specified")
	}
	return out, nil
}

// parseColumns splits a comma-separated column list, returning nil when empty
// (so callers can fall back to defaultColumns).
func parseColumns(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// parseExtraFilters converts "name=value" strings into Filter structs.
func parseExtraFilters(raw []string) ([]client.Filter, error) {
	var out []client.Filter
	for _, f := range raw {
		idx := strings.Index(f, "=")
		if idx <= 0 {
			return nil, fmt.Errorf("invalid filter %q: must be name=value", f)
		}
		out = append(out, client.Filter{
			FilterName: strings.TrimSpace(f[:idx]),
			Operator:   "=",
			Value:      f[idx+1:],
		})
	}
	return out, nil
}

// filterSCs returns a copy of cfg restricted to the named Security Centers.
func filterSCs(cfg *config.Config, names string) (*config.Config, error) {
	want := map[string]bool{}
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	var kept []config.SecurityCenter
	for _, sc := range cfg.SecurityCenters {
		if want[sc.Name] {
			kept = append(kept, sc)
		}
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("--sc %q matched no configured security centers", names)
	}
	out := *cfg
	out.SecurityCenters = kept
	return &out, nil
}

// severityLabels converts []int{4,3} → "4(Critical),3(High)" for log output.
func severityLabels(sevs []int) string {
	parts := make([]string, len(sevs))
	for i, s := range sevs {
		parts[i] = fmt.Sprintf("%d(%s)", s, vuln.SeverityName[s])
	}
	return strings.Join(parts, ",")
}

// newLogger creates a structured text logger writing to stderr.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
