// Package vuln provides concurrent vulnerability fetching from Tenable SC.
package vuln

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/kanaderajesh/go-sc-client/internal/client"
	"github.com/kanaderajesh/go-sc-client/internal/config"
)

// SeverityName maps severity integer codes to human-readable labels.
var SeverityName = map[int]string{
	0: "Info",
	1: "Low",
	2: "Medium",
	3: "High",
	4: "Critical",
}

// Options controls what and how data is fetched.
type Options struct {
	// Severities is the list of severity levels to query (0–4).
	Severities []int
	// PluginText is an optional substring filter applied against plugin output.
	PluginText string
	// ExtraFilters are additional API filters supplied by the caller.
	ExtraFilters []client.Filter
	// FilterMode is either "append" (add ExtraFilters to defaults) or
	// "override" (replace default pluginText filter with ExtraFilters).
	FilterMode string
	// Columns lists the SC field names to include in results.
	Columns []string
}

// Result carries the output (or error) for one SC × severity combination.
type Result struct {
	SCName   string
	Severity int
	Records  []json.RawMessage
	Err      error
}

// FetchAll launches one goroutine per (SecurityCenter × severity) pair so that
// all combinations run concurrently, maximising throughput across multiple SC
// instances and severity levels.
func FetchAll(cfg *config.Config, opts *Options, log *slog.Logger) []Result {
	columns := toColumns(opts.Columns)

	// Pre-allocate result slice so goroutines can write without a mutex.
	total := len(cfg.SecurityCenters) * len(opts.Severities)
	results := make([]Result, total)

	var wg sync.WaitGroup
	idx := 0

	for _, sc := range cfg.SecurityCenters {
		c := client.New(sc.URL, sc.AccessKey, sc.SecretKey, sc.SkipTLS, cfg.PageSize, log)
		scLog := log.With("sc", sc.Name, "url", sc.URL)

		for _, sev := range opts.Severities {
			wg.Add(1)
			// Capture loop variables for the goroutine.
			go func(slot int, scName string, cl *client.Client, l *slog.Logger, severity int) {
				defer wg.Done()

				filters := buildFilters(opts, severity)

				l.Info("fetching vulnerabilities",
					"severity", fmt.Sprintf("%d (%s)", severity, SeverityName[severity]),
					"pluginText", opts.PluginText,
					"filterMode", opts.FilterMode,
					"filterCount", len(filters),
				)

				records, err := cl.FetchAll(filters, columns)
				if err != nil {
					l.Error("fetch failed",
						"severity", SeverityName[severity],
						"error", err,
					)
				} else {
					l.Info("severity fetch complete",
						"severity", SeverityName[severity],
						"records", len(records),
					)
				}

				results[slot] = Result{
					SCName:   scName,
					Severity: severity,
					Records:  records,
					Err:      err,
				}
			}(idx, sc.Name, c, scLog, sev)

			idx++
		}
	}

	wg.Wait()
	return results
}

// buildFilters constructs the filter slice for one severity level, respecting
// the caller's FilterMode setting.
func buildFilters(opts *Options, severity int) []client.Filter {
	sevFilter := client.Filter{FilterName: "severity", Operator: "=", Value: strconv.Itoa(severity)}

	if opts.FilterMode == "override" && len(opts.ExtraFilters) > 0 {
		// Severity is always included; ExtraFilters replace everything else.
		return append([]client.Filter{sevFilter}, opts.ExtraFilters...)
	}

	// Default (append): severity + optional pluginText + any extra filters.
	base := []client.Filter{sevFilter}
	if opts.PluginText != "" {
		base = append(base, client.Filter{
			FilterName: "pluginText",
			Operator:   "=",
			Value:      opts.PluginText,
		})
	}
	return append(base, opts.ExtraFilters...)
}

// Flatten merges all Results into a flat slice of maps, tagging each row with
// the source SC name. Errors are returned separately so callers can log them
// without losing partial results.
func Flatten(results []Result) ([]map[string]any, []error) {
	var rows []map[string]any
	var errs []error

	for _, r := range results {
		if r.Err != nil {
			errs = append(errs, fmt.Errorf("[%s] severity %s: %w",
				r.SCName, SeverityName[r.Severity], r.Err))
			continue
		}
		for _, raw := range r.Records {
			var row map[string]any
			if err := json.Unmarshal(raw, &row); err != nil {
				errs = append(errs, fmt.Errorf("unmarshalling record: %w", err))
				continue
			}
			// Inject source metadata so downstream consumers can correlate results.
			row["_sc"] = r.SCName
			rows = append(rows, row)
		}
	}
	return rows, errs
}

// toColumns converts a slice of field name strings into Column structs.
func toColumns(names []string) []client.Column {
	cols := make([]client.Column, len(names))
	for i, n := range names {
		cols[i] = client.Column{Name: n}
	}
	return cols
}
