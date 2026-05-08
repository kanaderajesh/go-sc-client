// Package search implements client-side keyword search over Tenable SC vulnerabilities.
//
// For each (SecurityCenter × severity) pair one goroutine fetches all records page by page.
// Every record's pluginText field is checked against the configured keyword list
// (case-insensitive substring match). Matches are written to a per-severity CSV file whose
// name is derived from the user-supplied output prefix, e.g. prefix_Critical.csv.
//
// The CSV file is always flushed and closed — even on error — so partial results are
// preserved. Progress is printed to stderr after each page.
package search

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kanaderajesh/go-sc-client/internal/client"
	"github.com/kanaderajesh/go-sc-client/internal/config"
	"github.com/kanaderajesh/go-sc-client/internal/vuln"
)

// Options controls a full client-side keyword search run.
type Options struct {
	// Severities is the list of severity levels to query (0–4).
	Severities []int
	// ExtraFilters are additional API filters from the CLI --filter flag.
	ExtraFilters []client.Filter
	// FilterMode is "append" or "override" (same semantics as vuln.Options).
	FilterMode string
	// Keywords are the substrings searched case-insensitively against pluginText.
	// Must be non-empty; sourced from config search_keywords.
	Keywords []string
	// Columns lists the SC field names written to the CSV output (pluginText is
	// fetched automatically but only appears in the output when explicitly listed).
	Columns []string
	// OutputPrefix is the base path for per-severity CSV files.
	// Files are named <OutputPrefix>_<SeverityName>.csv.
	OutputPrefix string
	// DumpWriter receives request JSON bodies before each HTTP call (may be nil).
	DumpWriter io.Writer
}

// severityWriter owns the CSV writer and mutex for one severity-level output file.
type severityWriter struct {
	file   *os.File
	cw     *csv.Writer
	mu     sync.Mutex
}

// Run executes the full keyword search across all configured SCs and severities.
// One goroutine is launched per (SC × severity) pair. Each severity level writes
// matches to its own CSV file named <opts.OutputPrefix>_<SeverityName>.csv.
//
// All CSV files are flushed and closed before Run returns, regardless of errors.
func Run(cfg *config.Config, opts *Options, log *slog.Logger) error {
	// Open one CSV file per severity level.
	writers := make(map[int]*severityWriter, len(opts.Severities))
	for _, sev := range opts.Severities {
		path := fmt.Sprintf("%s_%s.csv", opts.OutputPrefix, vuln.SeverityName[sev])
		f, err := os.Create(path)
		if err != nil {
			// Close any already-opened files before returning.
			closeSeverityWriters(writers)
			return fmt.Errorf("creating output file %q: %w", path, err)
		}
		sw := &severityWriter{file: f, cw: csv.NewWriter(f)}
		writers[sev] = sw

		// Write CSV header: user columns + metadata.
		header := append(append([]string{}, opts.Columns...), "_matched_keyword", "_severity", "_sc")
		if err := sw.cw.Write(header); err != nil {
			closeSeverityWriters(writers)
			return fmt.Errorf("writing CSV header for %q: %w", path, err)
		}
		log.Info("opened search output file", "path", path, "severity", vuln.SeverityName[sev])
	}

	// Always flush and close all files before returning.
	defer closeSeverityWriters(writers)

	// fetchCols = user columns + pluginText (deduplicated) so we can search it.
	fetchCols := addIfMissing(opts.Columns, "pluginText")

	var (
		wg      sync.WaitGroup
		errsMu  sync.Mutex
		runErrs []error
	)

	for _, sc := range cfg.SecurityCenters {
		timeout := time.Duration(cfg.Timeout) * time.Second
		c := client.New(sc.URL, sc.AccessKey, sc.SecretKey, sc.SkipTLS, cfg.PageSize, timeout, log, opts.DumpWriter)

		// Per-SC merged config filters (global + SC-specific).
		scCfgFilters := vuln.ConfigToClientFilters(cfg.DefaultFilters)
		scCfgFilters = append(scCfgFilters, vuln.ConfigToClientFilters(sc.Filters)...)

		for _, sev := range opts.Severities {
			wg.Add(1)
			go func(scName string, cl *client.Client, severity int, cfgFilters []client.Filter, sw *severityWriter) {
				defer wg.Done()

				sevLabel := vuln.SeverityName[severity]
				vOpts := &vuln.Options{
					FilterMode:   opts.FilterMode,
					ExtraFilters: opts.ExtraFilters,
				}
				filters := vuln.BuildFilters(vOpts, severity, cfgFilters)

				log.Info("starting keyword search", "sc", scName, "severity", sevLabel, "keywords", opts.Keywords)

				err := cl.Stream(filters, fetchCols, func(records []json.RawMessage, page, seen, total int) error {
					pct := 0.0
					if total > 0 {
						pct = float64(seen) / float64(total) * 100
					}
					kwDisplay := strings.Join(opts.Keywords, ", ")
					fmt.Fprintf(os.Stderr,
						"[%s/%s] Page %d | %d/%d records (%.1f%%) | keywords: %s\n",
						scName, sevLabel, page, seen, total, pct, kwDisplay,
					)

					for _, raw := range records {
						var row map[string]any
						if err := json.Unmarshal(raw, &row); err != nil {
							log.Warn("unmarshal error", "sc", scName, "severity", sevLabel, "error", err)
							continue
						}
						pluginOut := strings.ToLower(asString(row["pluginText"]))

						for _, kw := range opts.Keywords {
							if strings.Contains(pluginOut, strings.ToLower(kw)) {
								record := buildCSVRecord(row, opts.Columns, kw, sevLabel, scName)
								sw.mu.Lock()
								_ = sw.cw.Write(record)
								sw.mu.Unlock()
							}
						}
					}
					return nil
				})

				if err != nil {
					log.Error("keyword search failed", "sc", scName, "severity", sevLabel, "error", err)
					errsMu.Lock()
					runErrs = append(runErrs, fmt.Errorf("[%s] severity %s: %w", scName, sevLabel, err))
					errsMu.Unlock()
					return
				}
				log.Info("keyword search done", "sc", scName, "severity", sevLabel)
			}(sc.Name, c, sev, scCfgFilters, writers[sev])
		}
	}

	wg.Wait()

	if len(runErrs) > 0 {
		for _, e := range runErrs {
			log.Error("search goroutine error", "error", e)
		}
		return fmt.Errorf("%d goroutine(s) failed; partial results written to %s_*.csv", len(runErrs), opts.OutputPrefix)
	}
	return nil
}

// closeSeverityWriters flushes and closes every open CSV file.
func closeSeverityWriters(writers map[int]*severityWriter) {
	for _, sw := range writers {
		sw.cw.Flush()
		sw.file.Close()
	}
}

// buildCSVRecord assembles one CSV row for a matching vulnerability record.
func buildCSVRecord(row map[string]any, columns []string, keyword, sevLabel, scName string) []string {
	record := make([]string, len(columns)+3)
	for i, col := range columns {
		record[i] = stringify(row[col])
	}
	record[len(columns)] = keyword
	record[len(columns)+1] = sevLabel
	record[len(columns)+2] = scName
	return record
}

// addIfMissing returns cols with item appended if not already present.
func addIfMissing(cols []string, item string) []string {
	for _, c := range cols {
		if c == item {
			return cols
		}
	}
	out := make([]string, len(cols)+1)
	copy(out, cols)
	out[len(cols)] = item
	return out
}

// asString extracts a plain string from an interface value (pluginText is typically a string).
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// stringify converts a JSON-decoded value to a printable CSV cell string.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case map[string]any:
		if name, ok := t["name"]; ok && name != "" {
			return fmt.Sprint(name)
		}
		if id, ok := t["id"]; ok {
			return fmt.Sprint(id)
		}
		b, _ := json.Marshal(t)
		return string(b)
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = stringify(e)
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprint(t)
	}
}
