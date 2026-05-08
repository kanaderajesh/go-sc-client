// sc-vuln is a command-line tool for fetching vulnerability data from one or
// more Tenable Security Center instances via the analysis REST API.
//
// Each requested severity level is processed in a separate goroutine so
// multiple severity × SC combinations run concurrently for maximum throughput.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kanaderajesh/go-sc-client/internal/client"
	"github.com/kanaderajesh/go-sc-client/internal/config"
	"github.com/kanaderajesh/go-sc-client/internal/output"
	"github.com/kanaderajesh/go-sc-client/internal/search"
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

// ── Command tree ─────────────────────────────────────────────────────────────

func newRootCmd() *cobra.Command {
	// Persistent flags are inherited by every subcommand.
	var (
		cfgFile     string
		severities  string
		filterMode  string
		extraFilter []string
		columns     string
		logLevel    string
		logFile     string
		timeout     int
	)

	// Root-only flags.
	var format string

	root := &cobra.Command{
		Use:   "sc-vuln [sc-name[,sc-name...]]",
		Short: "Fetch vulnerability data from Tenable Security Center",
		Long: `sc-vuln queries the Tenable Security Center /rest/analysis API for
vulnerability data. Each severity × SC combination runs in its own goroutine
for maximum concurrency.

The optional positional argument selects which Security Center(s) to query.
Omit it to query all configured SCs concurrently.

  sc-vuln                   # all configured SCs, all severities
  sc-vuln primary           # one SC by name
  sc-vuln primary,dr-site   # two SCs by name

Available subcommands:
  plugin-text          Filter vulnerabilities by plugin output text keyword
  full-search-keyword  Client-side keyword search with per-severity CSV output

Run 'sc-vuln <subcommand> --help' for subcommand-specific usage.
`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			scName := ""
			if len(args) > 0 {
				scName = args[0]
			}
			cfg, log, fileW, cleanup, err := prepare(cfgFile, scName, logLevel, logFile, timeout)
			if err != nil {
				return err
			}
			defer cleanup()

			dumpW := makeDumpWriter(fileW)

			sevList, err := parseSeverities(severities)
			if err != nil {
				return fmt.Errorf("--severity: %w", err)
			}
			extra, err := parseExtraFilters(extraFilter)
			if err != nil {
				return fmt.Errorf("--filter: %w", err)
			}
			cols := resolveColumns(columns, cfg.DefaultColumns)

			log.Info("starting",
				"security_centers", len(cfg.SecurityCenters),
				"severities", severityLabels(sevList),
				"filterMode", filterMode,
				"format", format,
				"columns", strings.Join(cols, ","),
			)

			results := vuln.FetchAll(cfg, &vuln.Options{
				Severities:   sevList,
				ExtraFilters: extra,
				FilterMode:   filterMode,
				Columns:      cols,
				DumpWriter:   dumpW,
			}, log)

			rows, errs := vuln.Flatten(results)
			for _, e := range errs {
				log.Error("partial failure", "error", e)
			}
			log.Info("done", "total_records", len(rows))

			displayCols := cols
			if len(displayCols) == 0 {
				displayCols = defaultColumns
			}
			return output.Format(os.Stdout, rows, displayCols, format)
		},
	}

	// Register persistent flags (available to root and all subcommands).
	pf := root.PersistentFlags()
	pf.StringVarP(&cfgFile, "config", "c", "config.yaml",
		"path to the YAML config file")
	pf.StringVarP(&severities, "severity", "s", "4,3,2,1,0",
		"comma-separated severity levels to query\n  0=Info  1=Low  2=Medium  3=High  4=Critical")
	pf.StringVarP(&filterMode, "filter-mode", "m", "append",
		"how filters are composed:\n  append   severity → config filters → --filter\n  override severity → --filter only (config filters skipped)")
	pf.StringArrayVarP(&extraFilter, "filter", "f", nil,
		"extra API filter as name=value (repeatable)\n  e.g. -f ip=10.0.0.1 -f repository=42")
	pf.StringVar(&columns, "columns", "",
		"comma-separated SC field names to return\n  defaults: "+strings.Join(defaultColumns, ","))
	pf.StringVarP(&logLevel, "log-level", "l", "",
		"log verbosity: debug | info | warn | error\n  (overrides config file log_level)")
	pf.StringVar(&logFile, "log-file", "",
		"path to a JSON log file (appended); request JSON is also written here\n  (overrides config file log_file)")
	pf.IntVar(&timeout, "timeout", 0,
		"HTTP request timeout in seconds (0 = use config file timeout, default 300)\n  increase when SC is slow or repositories are large")

	// Root-only flag.
	root.Flags().StringVarP(&format, "format", "o", "table",
		"output format: table | json | csv")

	root.AddCommand(
		newPluginTextCmd(&cfgFile, &severities, &filterMode, &extraFilter, &columns, &logLevel, &logFile, &timeout),
		newFullSearchCmd(&cfgFile, &severities, &filterMode, &extraFilter, &columns, &logLevel, &logFile, &timeout),
	)

	return root
}

// newPluginTextCmd returns the plugin-text subcommand.
//
// Usage: sc-vuln plugin-text <keyword> [sc-name[,sc-name...]] [flags]
func newPluginTextCmd(
	cfgFile, severities, filterMode *string,
	extraFilter *[]string,
	columns, logLevel, logFile *string,
	timeout *int,
) *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "plugin-text <keyword> [sc-name[,sc-name...]]",
		Short: "Filter vulnerabilities by plugin output text",
		Long: `Fetch vulnerabilities whose plugin output contains <keyword>.

The keyword is matched case-insensitively against each record's plugin output
text and is sent to the SC API as a pluginText filter.

Arguments:
  keyword    Required. Substring to match against plugin output text.
  sc-name    Optional. Comma-separated Security Center name(s) to query.
             Omit to query all configured SCs concurrently.

Flags:
  -o, --format string   Output format: table | json | csv  (default "table")

Inherited flags (see sc-vuln --help):
  -c, --config        -s, --severity    -m, --filter-mode
  -f, --filter        --columns         -l, --log-level
  --log-file          --timeout

Examples:
  sc-vuln plugin-text apache
  sc-vuln plugin-text apache primary
  sc-vuln plugin-text "log4j" primary,dr-site --severity 4,3
  sc-vuln plugin-text ssl --severity 4 --format csv > ssl_critical.csv
  sc-vuln plugin-text openssl --columns ip,dnsName,pluginID,name,cvssV3BaseScore
`,
		Args:         cobra.RangeArgs(1, 2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			keyword := args[0]
			scName := ""
			if len(args) == 2 {
				scName = args[1]
			}

			cfg, log, fileW, cleanup, err := prepare(*cfgFile, scName, *logLevel, *logFile, *timeout)
			if err != nil {
				return err
			}
			defer cleanup()

			dumpW := makeDumpWriter(fileW)

			sevList, err := parseSeverities(*severities)
			if err != nil {
				return fmt.Errorf("--severity: %w", err)
			}
			extra, err := parseExtraFilters(*extraFilter)
			if err != nil {
				return fmt.Errorf("--filter: %w", err)
			}
			cols := resolveColumns(*columns, cfg.DefaultColumns)

			log.Info("starting plugin-text search",
				"keyword", keyword,
				"security_centers", len(cfg.SecurityCenters),
				"severities", severityLabels(sevList),
				"filterMode", *filterMode,
				"format", format,
				"columns", strings.Join(cols, ","),
			)

			results := vuln.FetchAll(cfg, &vuln.Options{
				Severities:   sevList,
				PluginText:   keyword,
				ExtraFilters: extra,
				FilterMode:   *filterMode,
				Columns:      cols,
				DumpWriter:   dumpW,
			}, log)

			rows, errs := vuln.Flatten(results)
			for _, e := range errs {
				log.Error("partial failure", "error", e)
			}
			log.Info("done", "total_records", len(rows))

			displayCols := cols
			if len(displayCols) == 0 {
				displayCols = defaultColumns
			}
			return output.Format(os.Stdout, rows, displayCols, format)
		},
	}

	cmd.Flags().StringVarP(&format, "format", "o", "table",
		"output format: table | json | csv")

	return cmd
}

// newFullSearchCmd returns the full-search-keyword subcommand.
//
// Usage: sc-vuln full-search-keyword [sc-name[,sc-name...]] [flags]
func newFullSearchCmd(
	cfgFile, severities, filterMode *string,
	extraFilter *[]string,
	columns, logLevel, logFile *string,
	timeout *int,
) *cobra.Command {
	var outputPrefix string

	cmd := &cobra.Command{
		Use:   "full-search-keyword [sc-name[,sc-name...]]",
		Short: "Client-side keyword search with per-severity CSV output",
		Long: `Fetch all vulnerabilities from SC and search each record's pluginText field
against the keywords defined in config.yaml under search_keywords.

Each keyword is matched case-insensitively. Matching records are written to
per-severity CSV files. Each severity runs in its own goroutine and writes
to its own output file. CSV files are always flushed and closed even when an
error occurs, so partial results are never lost.

Keywords must be configured in config.yaml:

  search_keywords:
    - apache
    - log4j
    - openssl

Arguments:
  sc-name    Optional. Comma-separated Security Center name(s) to query.
             Omit to query all configured SCs concurrently.

Flags:
  -O, --output string   Base path for per-severity CSV output files (required).
                        Produces: <output>_Critical.csv, <output>_High.csv,
                                  <output>_Medium.csv, <output>_Low.csv,
                                  <output>_Info.csv

Inherited flags (see sc-vuln --help):
  -c, --config        -s, --severity    -m, --filter-mode
  -f, --filter        --columns         -l, --log-level
  --log-file          --timeout

CSV columns: <selected columns> + _matched_keyword + _severity + _sc

Progress is printed to stderr after each page:
  [primary/Critical] Page 1 | 1000/8542 records (11.7%) | keywords: apache, log4j

Examples:
  sc-vuln full-search-keyword --output /tmp/scan
  sc-vuln full-search-keyword primary --output ./results
  sc-vuln full-search-keyword primary,dr-site --severity 4,3 --output /tmp/scan
  sc-vuln full-search-keyword --severity 4 --columns ip,dnsName,pluginID,name --output /tmp/crit
`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputPrefix == "" {
				return fmt.Errorf("--output is required; specify a base path for the CSV output files")
			}

			scName := ""
			if len(args) > 0 {
				scName = args[0]
			}

			cfg, log, fileW, cleanup, err := prepare(*cfgFile, scName, *logLevel, *logFile, *timeout)
			if err != nil {
				return err
			}
			defer cleanup()

			keywords := cfg.SearchKeywords
			if len(keywords) == 0 {
				return fmt.Errorf("full-search-keyword requires search_keywords to be defined in the config file")
			}

			dumpW := makeDumpWriter(fileW)

			sevList, err := parseSeverities(*severities)
			if err != nil {
				return fmt.Errorf("--severity: %w", err)
			}
			extra, err := parseExtraFilters(*extraFilter)
			if err != nil {
				return fmt.Errorf("--filter: %w", err)
			}
			cols := resolveColumns(*columns, cfg.DefaultColumns)

			log.Info("starting full keyword search",
				"security_centers", len(cfg.SecurityCenters),
				"severities", severityLabels(sevList),
				"keywords", keywords,
				"outputPrefix", outputPrefix,
			)

			if err := search.Run(cfg, &search.Options{
				Severities:   sevList,
				ExtraFilters: extra,
				FilterMode:   *filterMode,
				Keywords:     keywords,
				Columns:      cols,
				OutputPrefix: outputPrefix,
				DumpWriter:   dumpW,
			}, log); err != nil {
				log.Error("full keyword search failed", "error", err)
				return err
			}

			log.Info("full keyword search complete",
				"files", fmt.Sprintf("%s_<Severity>.csv", outputPrefix))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPrefix, "output", "O", "",
		"base path for per-severity CSV output files (required)\n  produces <output>_Critical.csv, <output>_High.csv, ...")

	return cmd
}

// ── Shared setup helper ───────────────────────────────────────────────────────

// prepare loads config, resolves logging, opens the log file, and optionally
// restricts which SCs are queried. The returned cleanup func closes the log
// file; callers must defer it.
func prepare(cfgFile, scName, logLevel, logFile string, timeout int) (
	*config.Config, *slog.Logger, io.Writer, func(), error,
) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, nil, nil, func() {}, fmt.Errorf("config: %w", err)
	}
	if timeout > 0 {
		cfg.Timeout = timeout
	}

	effectiveLevel := resolveLevel(logLevel, cfg.LogLevel)
	effectiveLogFile := logFile
	if effectiveLogFile == "" {
		effectiveLogFile = cfg.LogFile
	}

	var fileW io.Writer
	cleanup := func() {}
	if effectiveLogFile != "" {
		f, err := os.OpenFile(effectiveLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, nil, func() {}, fmt.Errorf("opening log file %q: %w", effectiveLogFile, err)
		}
		fileW = f
		cleanup = func() { f.Close() }
	}

	log := buildLogger(logLevel, effectiveLevel, os.Stderr, fileW)

	if scName != "" {
		cfg, err = filterSCs(cfg, scName)
		if err != nil {
			cleanup()
			return nil, nil, nil, func() {}, err
		}
	}

	return cfg, log, fileW, cleanup, nil
}

// makeDumpWriter builds the writer used to dump request JSON before each HTTP
// call. When a log file is open, output goes to both stderr and the file.
func makeDumpWriter(fileW io.Writer) io.Writer {
	if fileW != nil {
		return io.MultiWriter(os.Stderr, fileW)
	}
	return os.Stderr
}

// resolveColumns returns the effective column list: CLI flag → config file → nil.
func resolveColumns(cliColumns string, cfgColumns []string) []string {
	if cols := parseColumns(cliColumns); len(cols) > 0 {
		return cols
	}
	return cfgColumns
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// parseColumns splits a comma-separated column list, returning nil when empty.
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
		return nil, fmt.Errorf("%q matched no configured security centers", names)
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

// resolveLevel picks the effective slog.Level from CLI flag and config string.
func resolveLevel(cliFlag, cfgLevel string) slog.Level {
	src := cliFlag
	if src == "" {
		src = cfgLevel
	}
	switch strings.ToLower(src) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// buildLogger creates a logger that writes text to stderr and, when fileW is
// non-nil, JSON records to fileW as well (both at effectiveLevel).
func buildLogger(cliFlag string, effectiveLevel slog.Level, stderr io.Writer, fileW io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: effectiveLevel}
	textH := slog.NewTextHandler(stderr, opts)

	if fileW == nil {
		return slog.New(textH)
	}
	jsonH := slog.NewJSONHandler(fileW, opts)
	return slog.New(&multiHandler{handlers: []slog.Handler{textH, jsonH}})
}

// ── multiHandler ─────────────────────────────────────────────────────────────

// multiHandler fans out every slog record to multiple handlers simultaneously.
type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: hs}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: hs}
}
