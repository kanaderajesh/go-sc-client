// Package client implements an HTTP client for the Tenable Security Center
// analysis REST API.
package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetries  = 3
	retryDelay  = 2 * time.Second // doubles after each attempt: 2s, 4s, 8s
)

// Filter represents a single query filter sent to the analysis API.
type Filter struct {
	FilterName string `json:"filterName"`
	Operator   string `json:"operator"`
	Value      string `json:"value"`
}

// analysisRequest is the JSON body for POST /rest/analysis.
// Per the Tenable SC REST API spec, startOffset/endOffset belong inside
// the query object and columns is an array of field-name strings.
type analysisRequest struct {
	Type       string   `json:"type"`
	SourceType string   `json:"sourceType"`
	Query      query    `json:"query"`
	SortField  string   `json:"sortField,omitempty"`
	SortDir    string   `json:"sortDir,omitempty"`
	// Columns is an array of SC field names to include in the response,
	// e.g. ["ip","pluginID","severity"]. An empty slice returns all fields.
	Columns []string `json:"columns,omitempty"`
}

type query struct {
	Type        string   `json:"type"`
	Tool        string   `json:"tool"`
	Filters     []Filter `json:"filters"`
	StartOffset string   `json:"startOffset"`
	EndOffset   string   `json:"endOffset"`
}

// analysisResponse mirrors the SC API response envelope.
type analysisResponse struct {
	Type     string `json:"type"`
	ErrorMsg string `json:"error_msg,omitempty"`
	Response struct {
		TotalRecords    string            `json:"totalRecords"`
		ReturnedRecords int               `json:"returnedRecords"`
		StartOffset     string            `json:"startOffset"`
		EndOffset       string            `json:"endOffset"`
		Results         []json.RawMessage `json:"results"`
	} `json:"response"`
}

// Client wraps an HTTP client pre-configured for a single Security Center.
type Client struct {
	baseURL   string
	accessKey string
	secretKey string
	pageSize  int
	httpC     *http.Client
	log       *slog.Logger
	// dumpW receives a pretty-printed copy of every request body before it is
	// sent. Pass nil to disable. Typically wired to both stderr and a log file
	// via io.MultiWriter so the JSON is visible on the console and persisted.
	dumpW io.Writer
}

// New creates a Client for one Security Center instance.
// timeout is the per-request deadline (covers the full round-trip including
// reading the response body). dumpW is where request JSON bodies are written
// before each call; pass nil to disable.
func New(baseURL, accessKey, secretKey string, skipTLS bool, pageSize int, timeout time.Duration, log *slog.Logger, dumpW io.Writer) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS}, //nolint:gosec
		MaxIdleConns:    10,
		IdleConnTimeout: 90 * time.Second,
		// ResponseHeaderTimeout guards against servers that accept the connection
		// but stall before sending the first response byte (the "waiting for headers"
		// variant of context deadline exceeded).
		ResponseHeaderTimeout: timeout,
	}
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		accessKey: accessKey,
		secretKey: secretKey,
		pageSize:  pageSize,
		httpC: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		log:   log,
		dumpW: dumpW,
	}
}

// PageFn is called by Stream after each page is fetched.
// page is 1-based; seen is cumulative records fetched; total is the
// API-reported total (0 when the response value is unparseable).
// Return a non-nil error to abort pagination early.
type PageFn func(records []json.RawMessage, page, seen, total int) error

// Stream pages through POST /rest/analysis and calls fn for each page.
// It stops when fn returns an error or the final page is reached.
func (c *Client) Stream(filters []Filter, columns []string, fn PageFn) error {
	seen := 0
	for page := 1; ; page++ {
		start := (page - 1) * c.pageSize
		req := analysisRequest{
			Type:       "vuln",
			SourceType: "cumulative",
			Query: query{
				Type:        "vuln",
				Tool:        "vulndetails",
				Filters:     filters,
				StartOffset: strconv.Itoa(start),
				EndOffset:   strconv.Itoa(start + c.pageSize),
			},
			SortField: "severity",
			SortDir:   "desc",
			Columns:   columns,
		}

		resp, err := c.post(req)
		if err != nil {
			return err
		}

		seen += len(resp.Response.Results)
		total, _ := strconv.Atoi(resp.Response.TotalRecords)

		c.log.Debug("stream page fetched",
			"page", page,
			"seen", seen,
			"total", total,
		)

		if err := fn(resp.Response.Results, page, seen, total); err != nil {
			return err
		}

		if resp.Response.ReturnedRecords < c.pageSize {
			break
		}
	}
	return nil
}

// FetchAll pages through POST /rest/analysis and returns every matching record
// as a raw JSON object. It handles pagination automatically.
// columns is the list of SC field names to return (e.g. ["ip","pluginID","severity"]);
// pass nil or an empty slice to request all available fields.
func (c *Client) FetchAll(filters []Filter, columns []string) ([]json.RawMessage, error) {
	var all []json.RawMessage

	for start := 0; ; start += c.pageSize {
		req := analysisRequest{
			Type:       "vuln",
			SourceType: "cumulative",
			Query: query{
				Type:        "vuln",
				Tool:        "vulndetails",
				Filters:     filters,
				StartOffset: strconv.Itoa(start),
				EndOffset:   strconv.Itoa(start + c.pageSize),
			},
			SortField: "severity",
			SortDir:   "desc",
			Columns:   columns,
		}

		resp, err := c.post(req)
		if err != nil {
			return nil, err
		}

		all = append(all, resp.Response.Results...)

		c.log.Debug("page fetched",
			"startOffset", start,
			"returned", resp.Response.ReturnedRecords,
			"total", resp.Response.TotalRecords,
		)

		// Last page: fewer results than requested means we have everything.
		if resp.Response.ReturnedRecords < c.pageSize {
			break
		}
	}

	return all, nil
}

// post marshals req, dumps it, and sends it to /rest/analysis with automatic
// retry on transient failures (network errors, timeouts, HTTP 5xx).
// Retries use exponential backoff: 2 s → 4 s → 8 s.
func (c *Client) post(body analysisRequest) (*analysisResponse, error) {
	// Pretty-print and dump request JSON to console + log file before sending.
	if c.dumpW != nil {
		pretty, _ := json.MarshalIndent(body, "", "  ")
		fmt.Fprintf(c.dumpW,
			"\n=== Request: POST %s/rest/analysis (offset %s) ===\n%s\n%s\n\n",
			c.baseURL,
			body.Query.StartOffset,
			pretty,
			strings.Repeat("=", 60),
		)
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	c.log.Debug("POST /rest/analysis", "url", c.baseURL, "startOffset", body.Query.StartOffset, "endOffset", body.Query.EndOffset)

	var (
		raw     []byte
		status  int
		lastErr error
	)

	backoff := retryDelay
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			c.log.Warn("retrying request after failure",
				"attempt", attempt,
				"maxRetries", maxRetries,
				"backoff", backoff.String(),
				"error", lastErr,
			)
			time.Sleep(backoff)
			backoff *= 2
		}

		// Rebuild the request each attempt: the body reader is consumed after
		// the first read, and http.Request must not be reused after a send.
		req, err := http.NewRequest(http.MethodPost, c.baseURL+"/rest/analysis", bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("building HTTP request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-ApiKey", fmt.Sprintf("accessKey=%s; secretKey=%s", c.accessKey, c.secretKey))

		httpResp, err := c.httpC.Do(req)
		if err != nil {
			// Network-level error (includes context deadline exceeded / timeout).
			lastErr = fmt.Errorf("HTTP request failed: %w", err)
			continue
		}

		raw, err = io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading response body: %w", err)
			continue
		}

		status = httpResp.StatusCode
		if status >= 500 {
			// Server-side error — worth retrying.
			lastErr = fmt.Errorf("SC returned HTTP %d: %s", status, clip(string(raw), 300))
			continue
		}

		// Any non-5xx response (including 4xx) is not retried.
		lastErr = nil
		break
	}

	if lastErr != nil {
		return nil, lastErr
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("SC returned HTTP %d: %s", status, clip(string(raw), 300))
	}

	var resp analysisResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parsing response JSON: %w", err)
	}
	if resp.ErrorMsg != "" {
		return nil, fmt.Errorf("SC API error: %s", resp.ErrorMsg)
	}

	return &resp, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
