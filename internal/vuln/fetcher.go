// Package vuln provides concurrent vulnerability fetching from Tenable SC.
package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"

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
	// ExtraFilters are additional API filters supplied via the CLI --filter flag.
	ExtraFilters []client.Filter
	// FilterMode is either "append" (add to config + pluginText defaults) or
	// "override" (use only severity + ExtraFilters; skip config and pluginText).
	FilterMode string
	// Columns lists the SC field names to include in results.
	Columns []string
	// DumpWriter is where request JSON bodies are written before each HTTP call.
	// Typically io.MultiWriter(os.Stderr, logFile). Nil disables dumping.
	DumpWriter io.Writer
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
//
// Config filters are merged per SC: global default_filters first, then the
// per-SC filters block, then CLI filters (behaviour depends on FilterMode).
func FetchAll(cfg *config.Config, opts *Options, log *slog.Logger) []Result {
	// opts.Columns is passed directly as []string; the API accepts an array of field names.
	columns := opts.Columns

	// Pre-allocate result slice indexed by goroutine slot — no mutex needed.
	total := len(cfg.SecurityCenters) * len(opts.Severities)
	results := make([]Result, total)

	var wg sync.WaitGroup
	idx := 0

	for _, sc := range cfg.SecurityCenters {
		timeout := time.Duration(cfg.Timeout) * time.Second
		c := client.New(sc.URL, sc.AccessKey, sc.SecretKey, sc.SkipTLS, cfg.PageSize, timeout, log, opts.DumpWriter)
		scLog := log.With("sc", sc.Name, "url", sc.URL)

		// Merge global default_filters + this SC's filters into one ordered slice.
		scConfigFilters := ConfigToClientFilters(cfg.DefaultFilters)
		scConfigFilters = append(scConfigFilters, ConfigToClientFilters(sc.Filters)...)

		for _, sev := range opts.Severities {
			wg.Add(1)
			go func(slot int, scName string, cl *client.Client, l *slog.Logger, severity int, cfgFilters []client.Filter) {
				defer wg.Done()

				filters := BuildFilters(opts, severity, cfgFilters)

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
			}(idx, sc.Name, c, scLog, sev, scConfigFilters)

			idx++
		}
	}

	wg.Wait()
	return results
}

// BuildFilters assembles the final filter list for one severity level.
//
// append mode (default):
//
//	severity → configFilters (from config file) → pluginText (CLI) → ExtraFilters (CLI)
//
// override mode:
//
//	severity → ExtraFilters (CLI only; config and pluginText are skipped)
func BuildFilters(opts *Options, severity int, configFilters []client.Filter) []client.Filter {
	sevFilter := client.Filter{FilterName: "severity", Operator: "=", Value: strconv.Itoa(severity)}

	if opts.FilterMode == "override" {
		// Severity is always kept; everything else is replaced by CLI --filter values.
		return append([]client.Filter{sevFilter}, opts.ExtraFilters...)
	}

	// Append mode: start with severity, layer config filters, then CLI additions.
	out := []client.Filter{sevFilter}
	out = append(out, configFilters...)
	if opts.PluginText != "" {
		out = append(out, client.Filter{
			FilterName: "pluginText",
			Operator:   "=",
			Value:      opts.PluginText,
		})
	}
	return append(out, opts.ExtraFilters...)
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
			// Tag each row so downstream consumers know which SC produced it.
			row["_sc"] = r.SCName
			rows = append(rows, row)
		}
	}
	return rows, errs
}

// ConfigToClientFilters converts config.FilterConfig slice to client.Filter slice.
func ConfigToClientFilters(cfgFilters []config.FilterConfig) []client.Filter {
	out := make([]client.Filter, len(cfgFilters))
	for i, f := range cfgFilters {
		op := f.Operator
		if op == "" {
			op = "="
		}
		out[i] = client.Filter{FilterName: f.Name, Operator: op, Value: f.Value}
	}
	return out
}

