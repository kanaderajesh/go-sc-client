# go-sc-client (`sc-vuln`)

A concurrent Go CLI tool for fetching and searching vulnerability data from one
or more [Tenable Security Center](https://www.tenable.com/products/tenable-security-center)
instances via the `/rest/analysis` REST API.

---

## Table of contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Command reference](#command-reference)
5. [Usage examples](#usage-examples)
   - [sc-vuln — basic fetch](#sc-vuln--basic-fetch)
   - [sc-vuln plugin-text — filter by keyword](#sc-vuln-plugin-text--filter-by-keyword)
   - [sc-vuln full-search-keyword — client-side search](#sc-vuln-full-search-keyword--client-side-search)
6. [Output formats](#output-formats)
7. [Available SC field names](#available-sc-field-names)
8. [Troubleshooting](#troubleshooting)

---

## Requirements

| Requirement | Details |
|---|---|
| Go | 1.21 or later (`log/slog` from stdlib) |
| Tenable SC | 5.13 or later (API key authentication) |
| Network | HTTPS access from this machine to each SC instance |

### API key authentication

The tool authenticates with Tenable SC API keys (`X-ApiKey` header). To generate them:

1. Log in to Tenable Security Center as an administrator.
2. Go to **Users → API Keys**.
3. Click **Generate** and copy both the **Access Key** and **Secret Key**.
4. The user account needs at least **Read** access to the repositories you intend to query.

---

## Installation

```bash
git clone https://github.com/kanaderajesh/go-sc-client.git
cd go-sc-client
go build -o sc-vuln ./cmd/
```

The compiled binary is self-contained with no runtime dependencies.

---

## Configuration

Copy the example and fill in your credentials:

```bash
cp config.yaml.example config.yaml
```

### Full config.yaml reference

```yaml
# ── Security Centers ─────────────────────────────────────────────────────────
# List every Tenable Security Center instance to query.
# All configured SCs are queried concurrently unless a specific SC name is
# passed as a positional argument on the command line.
security_centers:
  - name: primary                        # Label used in output and SC selection argument
    url: https://sc1.example.com         # Base URL of the SC web interface
    access_key: REPLACE_WITH_ACCESS_KEY  # SC → Users → API Keys → Access Key
    secret_key: REPLACE_WITH_SECRET_KEY  # SC → Users → API Keys → Secret Key
    # skip_tls: true                     # Disable TLS cert verification (lab/dev only)

    # Per-SC filters — applied only when querying this SC.
    # Merged after default_filters, before any CLI --filter values.
    # filters:
    #   - name: repository
    #     value: "1"
    #   - name: ip
    #     operator: "="
    #     value: "10.0.0.0/8"

  - name: dr-site
    url: https://sc2.example.com
    access_key: REPLACE_WITH_ACCESS_KEY
    secret_key: REPLACE_WITH_SECRET_KEY
    # filters:
    #   - name: repository
    #     value: "2"

# ── Global filters ───────────────────────────────────────────────────────────
# Applied to EVERY query regardless of which SC is targeted.
# Inserted between the mandatory severity filter and CLI --filter values.
# Ignored when --filter-mode override is used on the command line.
#
# default_filters:
#   - name: pluginText
#     value: apache
#   - name: exploitAvailable
#     operator: "="
#     value: "true"

# ── Default output columns ───────────────────────────────────────────────────
# Columns to request from SC and display in output.
# Overridden at runtime by --columns. When omitted, a built-in set is used:
#   _sc ip dnsName pluginID severity name protocol port firstSeen lastSeen
#
# default_columns:
#   - ip
#   - dnsName
#   - pluginID
#   - severity
#   - name
#   - protocol
#   - port
#   - firstSeen
#   - lastSeen
#   - cvssV3BaseScore
#   - vprScore
#   - exploitAvailable

# ── Keyword search ───────────────────────────────────────────────────────────
# Keywords used by the full-search-keyword subcommand.
# Each keyword is matched case-insensitively against the pluginText field of
# every vulnerability record. Matches are written to per-severity CSV files.
# Required when using: sc-vuln full-search-keyword
#
# search_keywords:
#   - apache
#   - log4j
#   - openssl
#   - spring

# ── Logging ──────────────────────────────────────────────────────────────────
# Log verbosity: debug | info | warn | error  (default: info)
# Override at runtime with --log-level.
log_level: info

# Path to a JSON structured log file (created/appended automatically).
# All slog messages AND request JSON bodies are written here.
# Override at runtime with --log-file. Leave empty to disable file logging.
log_file: ""

# ── HTTP settings ─────────────────────────────────────────────────────────────
# HTTP request timeout in seconds (default: 300).
# Covers the full round-trip including response body download.
# Retries are attempted up to 3 times with exponential backoff (2 s, 4 s, 8 s)
# on network errors, timeouts, and HTTP 5xx responses.
# Override at runtime with --timeout.
timeout: 300

# Number of records fetched per API page (default: 1000).
page_size: 1000
```

### Filter precedence (append mode)

```
severity  →  default_filters (config)  →  per-SC filters (config)  →  --filter (CLI)
```

Use `--filter-mode override` to send only `severity` + `--filter` values and skip all config filters.

---

## Command reference

```
sc-vuln [sc-name[,sc-name...]] [flags]          # basic fetch
sc-vuln plugin-text <keyword> [sc-name] [flags]  # filter by plugin text
sc-vuln full-search-keyword [sc-name] [flags]    # client-side keyword search
```

### Global flags (available on all commands)

| Flag | Short | Default | Description |
|---|---|---|---|
| `--config` | `-c` | `config.yaml` | Path to the YAML config file |
| `--severity` | `-s` | `4,3,2,1,0` | Severity levels: `0`=Info `1`=Low `2`=Medium `3`=High `4`=Critical |
| `--filter` | `-f` | — | Extra API filter `name=value` (repeatable) |
| `--filter-mode` | `-m` | `append` | `append` or `override` (see filter precedence above) |
| `--columns` | — | built-in set | Comma-separated SC field names to return |
| `--log-level` | `-l` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `--log-file` | — | — | Path to JSON log file (appended); request bodies written here too |
| `--timeout` | — | `0` (config) | HTTP timeout in seconds; `0` uses the config file value (default 300) |

### `sc-vuln` — basic fetch

```
sc-vuln [sc-name[,sc-name...]] [flags]
```

Fetches all matching vulnerabilities and writes them to stdout.

| Flag | Short | Default | Description |
|---|---|---|---|
| `--format` | `-o` | `table` | Output format: `table` \| `json` \| `csv` |

### `sc-vuln plugin-text` — filter by keyword

```
sc-vuln plugin-text <keyword> [sc-name[,sc-name...]] [flags]
```

Sends `keyword` to the SC API as a `pluginText` filter (case-insensitive substring match
against plugin output). Results are written to stdout.

| Argument / Flag | Required | Description |
|---|---|---|
| `keyword` | Yes | Substring to match against plugin output text |
| `sc-name` | No | Comma-separated SC name(s); omit to query all SCs |
| `--format` / `-o` | No | Output format: `table` \| `json` \| `csv` (default `table`) |

### `sc-vuln full-search-keyword` — client-side search

```
sc-vuln full-search-keyword [sc-name[,sc-name...]] --output <prefix> [flags]
```

Fetches every vulnerability and checks each record's `pluginText` field locally
against the keywords in `config.yaml → search_keywords`. Matches are written to
per-severity CSV files named `<prefix>_<Severity>.csv`.

| Argument / Flag | Required | Description |
|---|---|---|
| `sc-name` | No | Comma-separated SC name(s); omit to query all SCs |
| `--output` / `-O` | **Yes** | Base path for CSV output files |

**Config requirement:** `search_keywords` must be defined in `config.yaml`.

**Output files produced** (one per queried severity):

```
<prefix>_Critical.csv
<prefix>_High.csv
<prefix>_Medium.csv
<prefix>_Low.csv
<prefix>_Info.csv
```

**CSV columns:** your selected columns + `_matched_keyword` + `_severity` + `_sc`

**CSV files are always flushed and closed** — even when an error occurs — so partial
results are never lost.

---

## Usage examples

### sc-vuln — basic fetch

```bash
# All vulnerabilities, all severities, table output
./sc-vuln

# Critical and High only
./sc-vuln --severity 4,3

# Query one specific SC
./sc-vuln primary

# Query two specific SCs, Critical only
./sc-vuln primary,dr-site --severity 4

# Custom columns
./sc-vuln --columns ip,dnsName,pluginID,name,cvssV3BaseScore,vprScore,exploitAvailable

# JSON output, pipe to jq
./sc-vuln --severity 4 --format json | jq '.[] | {ip, name, cvssV3BaseScore}'

# CSV output to file
./sc-vuln --severity 4,3 --format csv > critical_high.csv

# Extra API filters (append mode — stacked on top of config filters)
./sc-vuln --severity 4 --filter ip=192.168.1.100
./sc-vuln --severity 4,3 --filter ip=192.168.1.100 --filter port=443

# Override mode — only severity + your --filter values are sent
./sc-vuln --severity 4,3 --filter-mode override --filter ip=10.0.0.0/24

# Debug: show request JSON and pagination details
./sc-vuln --severity 4 --log-level debug

# Slow SC — increase timeout
./sc-vuln --timeout 600

# Structured log file
./sc-vuln --log-file /var/log/sc-vuln.json
```

---

### sc-vuln plugin-text — filter by keyword

**Config** — no special config required beyond the `security_centers` block.

```bash
# All apache vulnerabilities across all severities
./sc-vuln plugin-text apache

# Apache on one SC, Critical only
./sc-vuln plugin-text apache primary --severity 4

# Log4j across two SCs, Critical + High, CSV output
./sc-vuln plugin-text log4j primary,dr-site --severity 4,3 --format csv > log4j.csv

# SSL/TLS on port 443
./sc-vuln plugin-text ssl --severity 4,3 --filter port=443

# Custom columns
./sc-vuln plugin-text openssl \
  --columns ip,dnsName,pluginID,name,cvssV3BaseScore,solution \
  --format csv > openssl_vulns.csv

# Use override mode — sends only severity + pluginText, skips config default_filters
./sc-vuln plugin-text apache --filter-mode override --severity 4
```

---

### sc-vuln full-search-keyword — client-side search

**Required config settings:**

```yaml
# config.yaml
search_keywords:
  - apache
  - log4j
  - openssl
  - spring

# Optional — tune columns written to every CSV row
default_columns:
  - ip
  - dnsName
  - pluginID
  - name
  - severity
  - cvssV3BaseScore
  - solution
  - pluginText
```

```bash
# Basic: search all SCs, all severities
# Produces: /tmp/scan_Critical.csv, /tmp/scan_High.csv, ...
./sc-vuln full-search-keyword --output /tmp/scan

# Search one SC only
./sc-vuln full-search-keyword primary --output ./results

# Search two SCs, Critical and High only
./sc-vuln full-search-keyword primary,dr-site --severity 4,3 --output /tmp/scan

# Custom columns in the CSV
./sc-vuln full-search-keyword \
  --severity 4,3 \
  --columns ip,dnsName,pluginID,name,cvssV3BaseScore,solution \
  --output /tmp/crit_high

# Date-stamped output files
./sc-vuln full-search-keyword --output ./scan_$(date +%Y%m%d)

# Debug: log every request and page
./sc-vuln full-search-keyword --output /tmp/scan --log-level debug --log-file /tmp/sc.log
```

**Console progress** (stderr, one line per page per SC/severity):

```
[primary/Critical] Page 1 | 1000/8542 records (11.7%) | keywords: apache, log4j
[primary/Critical] Page 2 | 2000/8542 records (23.4%) | keywords: apache, log4j
[dr-site/High]     Page 1 |  500/2301 records (21.7%)  | keywords: apache, log4j
```

**Sample CSV output** (`/tmp/scan_Critical.csv`):

```
ip,dnsName,pluginID,name,cvssV3BaseScore,solution,_matched_keyword,_severity,_sc
10.0.0.1,web01.corp.com,104743,Apache HTTP Server,...,7.5,Update Apache...,apache,Critical,primary
10.0.0.5,app01.corp.com,94437,Apache Struts RCE,...,9.8,Apply patch...,apache,Critical,dr-site
```

---

## Output formats

### table (default)

Human-readable aligned table on stdout. Suitable for interactive inspection.

```
_sc       ip          dnsName          pluginID  severity  name
--------  ----------  ---------------  --------  --------  ------------------
primary   10.0.0.1    web01.corp.com   104743    Critical  Apache HTTP Server
primary   10.0.0.2    db01.corp.com    51192     High      SSL Certificate Expired
```

### json

Pretty-printed JSON array on stdout. Contains all returned fields plus `_sc`.

```bash
./sc-vuln --format json | jq '.[] | select(.severity.name == "Critical")'
```

```json
[
  {
    "_sc": "primary",
    "ip": "10.0.0.1",
    "pluginID": "104743",
    "severity": { "id": "4", "name": "Critical" },
    "cvssV3BaseScore": "9.8"
  }
]
```

### csv

RFC 4180 CSV with a header row, columns matching `--columns` selection.

```bash
./sc-vuln --format csv > results.csv
./sc-vuln plugin-text apache --format csv > apache.csv
```

---

## Available SC field names

| Field | Description |
|---|---|
| `ip` | Asset IP address |
| `dnsName` | DNS hostname |
| `pluginID` | Tenable plugin identifier |
| `name` | Vulnerability / plugin name |
| `severity` | Severity object (`id` + `name`) |
| `protocol` | Network protocol (TCP / UDP / ICMP) |
| `port` | Port number |
| `firstSeen` | Timestamp when vuln was first detected |
| `lastSeen` | Timestamp of most recent detection |
| `cvssV3BaseScore` | CVSS v3 base score |
| `cvssV3Vector` | CVSS v3 vector string |
| `cvssBaseScore` | CVSS v2 base score |
| `vprScore` | Vulnerability Priority Rating score |
| `exploitAvailable` | Whether a public exploit exists |
| `exploitEase` | Exploit ease description |
| `synopsis` | Short description of the vulnerability |
| `solution` | Recommended remediation |
| `pluginText` | Full plugin output text (large; used by full-search-keyword) |
| `family` | Plugin family |
| `repository` | SC repository object |
| `netbiosName` | NetBIOS name of the asset |
| `operatingSystem` | Detected OS |
| `macAddress` | MAC address |
| `patchPubDate` | Date the patch was published |
| `pluginPubDate` | Date the plugin was published |

`_sc` is a synthetic field added by this tool — it contains the Security Center
name from config and is always included in output when querying multiple SCs.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `HTTP 403` | Invalid or expired API keys | Regenerate keys in SC → Users → API Keys |
| `HTTP 401` | Wrong `X-ApiKey` header format | Check `access_key` / `secret_key` in config |
| `certificate signed by unknown authority` | Self-signed SC cert | Add `skip_tls: true` to the SC entry in config |
| `context deadline exceeded` | SC slow or unreachable | Check connectivity; add `--timeout 600` |
| `timeout awaiting response headers` | SC accepts connection but stalls | Same as above — increase `--timeout` |
| Empty results | Filter too restrictive | Run `--log-level debug` to see exact filters sent |
| `no security_centers defined` | Config file missing or wrong path | Pass `-c /path/to/config.yaml` |
| `full-search-keyword requires search_keywords` | Missing config section | Add `search_keywords` list to `config.yaml` |
| `"primary" matched no configured security centers` | SC name typo | Names must match the `name` field in `config.yaml` exactly |
