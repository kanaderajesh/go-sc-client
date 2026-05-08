// Package output formats vulnerability rows for display.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Format writes rows to w using the requested format (table, json, or csv).
// columns controls the field order for table and csv output; json always
// emits all fields present in each row.
func Format(w io.Writer, rows []map[string]any, columns []string, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSON(w, rows)
	case "csv":
		return writeCSV(w, rows, columns)
	default:
		return writeTable(w, rows, columns)
	}
}

func writeJSON(w io.Writer, rows []map[string]any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func writeCSV(w io.Writer, rows []map[string]any, columns []string) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(columns); err != nil {
		return err
	}
	for _, row := range rows {
		record := make([]string, len(columns))
		for i, col := range columns {
			record[i] = stringify(row[col])
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeTable(w io.Writer, rows []map[string]any, columns []string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Header row.
	fmt.Fprintln(tw, strings.Join(columns, "\t"))
	// Separator line.
	seps := make([]string, len(columns))
	for i, col := range columns {
		seps[i] = strings.Repeat("-", len(col))
	}
	fmt.Fprintln(tw, strings.Join(seps, "\t"))

	for _, row := range rows {
		vals := make([]string, len(columns))
		for i, col := range columns {
			vals[i] = stringify(row[col])
		}
		fmt.Fprintln(tw, strings.Join(vals, "\t"))
	}
	return tw.Flush()
}

// stringify converts a JSON-decoded value to a printable string.
// Tenable SC returns many fields as objects with "id"/"name" sub-fields
// (e.g. severity, repository, family), so we unwrap those automatically.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		// JSON numbers decode as float64; format integers without decimals.
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
		// Prefer "name" → "id" → JSON dump for object fields.
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
