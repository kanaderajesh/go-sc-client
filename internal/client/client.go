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
// dumpW is where request JSON bodies are written before each call; nil disables dumping.
func New(baseURL, accessKey, secretKey string, skipTLS bool, pageSize int, log *slog.Logger, dumpW io.Writer) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS}, //nolint:gosec
		MaxIdleConns:    10,
		IdleConnTimeout: 90 * time.Second,
	}
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		accessKey: accessKey,
		secretKey: secretKey,
		pageSize:  pageSize,
		httpC: &http.Client{
			Timeout:   120 * time.Second,
			Transport: transport,
		},
		log:   log,
		dumpW: dumpW,
	}
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

// post marshals req, dumps it, sends it to /rest/analysis, and returns the parsed response.
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

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/rest/analysis", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("building HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Tenable SC API key authentication header (SC 5.13+).
	req.Header.Set("X-ApiKey", fmt.Sprintf("accessKey=%s; secretKey=%s", c.accessKey, c.secretKey))

	c.log.Debug("POST /rest/analysis", "url", c.baseURL, "startOffset", body.Query.StartOffset, "endOffset", body.Query.EndOffset)

	httpResp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SC returned HTTP %d: %s", httpResp.StatusCode, clip(string(raw), 300))
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
