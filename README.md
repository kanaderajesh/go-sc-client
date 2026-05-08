# go-sc-client

A concurrent Go CLI tool for fetching vulnerability data from one or more
[Tenable Security Center](https://www.tenable.com/products/tenable-security-center)
instances via the `/rest/analysis` REST API.

## Requirements

| Requirement | Details |
|---|---|
| Go | 1.21 or later (uses `log/slog` from stdlib) |
| Tenable SC | 5.13 or later (API key authentication) |
| Network | HTTPS access from the machine running `sc-vuln` to each SC instance |

### API key authentication

The tool uses Tenable SC API keys (`X-ApiKey` header). To generate keys:

1. Log in to Tenable Security Center as an administrator.
2. Go to **Users → API Keys**.
3. Click **Generate** and copy both the **Access Key** and **Secret Key**.
4. The user account associated with the keys needs at least **Read** access to
   the repositories you intend to query.

---

## Installation

```bash
git clone https://github.com/kanaderajesh/go-sc-client.git
cd go-sc-client
go build -o sc-vuln ./cmd/
```

The compiled binary `sc-vuln` (or `sc-vuln.exe` on Windows) is self-contained
and has no runtime dependencies.

---

## Configuration

Copy the example config and fill in your credentials:

```bash
cp config.yaml.example config.yaml
```

### config.yaml reference

```yaml
# One entry per Tenable Security Center instance.
# All instances are queried concurrently unless --sc restricts the list.
security_centers:
  - name: primary                        # arbitrary label used in output and --sc flag
    url: https://sc1.example.com         # base URL of the SC web interface
    access_key: REPLACE_WITH_ACCESS_KEY  # generated in SC → Users → API Keys
    secret_key: REPLACE_WITH_SECRET_KEY
    # skip_tls: true                     # disable TLS verification (lab use only)

  - name: dr-site
    url: https://sc2.example.com
    access_key: REPLACE_WITH_ACCESS_KEY
    secret_key: REPLACE_WITH_SECRET_KEY

# Log verbosity written to stderr: debug | info | warn | error  (default: info)
log_level: info

# Records fetched per API page (default: 1000).
page_size: 1000

# Keywords for --full-search-keyword mode (case-insensitive substring match
# against each record's pluginText field). One CSV file per severity is produced.
# search_keywords:
#   - apache
#   - log4j
#   - openssl
```

Multiple Security Centers are queried in parallel — there is no limit on the
number of entries.

---

## How it works

```
config.yaml
    │
    ▼
 sc-vuln CLI
    │
    ├── goroutine: primary × Critical (severity 4)  ──▶ SC1 /rest/analysis (paged)
    ├── goroutine: primary × High     (severity 3)  ──▶ SC1 /rest/analysis (paged)
    ├── goroutine: primary × Medium   (severity 2)  ──▶ SC1 /rest/analysis (paged)
    ├── goroutine: primary × Low      (severity 1)  ──▶ SC1 /rest/analysis (paged)
    ├── goroutine: primary × Info     (severity 0)  ──▶ SC1 /rest/analysis (paged)
    ├── goroutine: dr-site × Critical (severity 4)  ──▶ SC2 /rest/analysis (paged)
    └── ...
    │
    ▼  (wait for all goroutines)
 merge + format → stdout
```

One goroutine is launched per *(Security Center × severity)* combination.
Each goroutine handles its own pagination loop automatically (page size
controlled by `page_size` in config). Results are merged and written to
stdout once all goroutines have finished.

---

## Command-line reference

```
sc-vuln [sc-name[,sc-name...]] [flags]

Arguments:
  sc-name   Optional comma-separated list of Security Center names to query.
            Names must match the name field in config.yaml.
            Omit to query all configured SCs concurrently.

              sc-vuln                   # all configured SCs
              sc-vuln primary           # one SC by name
              sc-vuln primary,dr-site   # two SCs by name

Flags:
  -c, --config string              Path to the YAML config file (default "config.yaml")
  -p, --plugin-text string         Filter by plugin text — substring match against plugin output
  -s, --severity string            Comma-separated severity levels (default "4,3,2,1,0")
                                     0=Info  1=Low  2=Medium  3=High  4=Critical
  -f, --filter stringArray         Extra API filter as name=value (repeatable)
  -m, --filter-mode string         How --filter interacts with built-in filters (default "append")
                                     append   add --filter values alongside severity/pluginText
                                     override replace everything except severity with --filter values
      --columns string             Comma-separated SC field names to return
      --full-search-keyword string Enable full client-side keyword search.
                                   Value is the CSV output file prefix.
                                   One file per severity: <prefix>_Critical.csv, etc.
                                   Keywords come from config search_keywords list.
  -o, --format string              Output format: table | json | csv (default "table")
  -l, --log-level string           Log verbosity: debug | info | warn | error
      --timeout int                HTTP request timeout in seconds (0 = use config, default 300)
  -h, --help                       Show this help
```

### Default output columns

When `--columns` is not specified, the following fields are returned:

```
_sc  ip  dnsName  pluginID  severity  name  protocol  port  firstSeen  lastSeen
```

`_sc` is a synthetic field added by the tool that contains the Security Center
name from the config, useful when querying multiple instances.

### Available SC field names (selection)

| Field | Description |
|---|---|
| `ip` | Asset IP address |
| `dnsName` | DNS hostname |
| `pluginID` | Tenable plugin identifier |
| `name` | Vulnerability / plugin name |
| `severity` | Severity object (id + name) |
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
| `family` | Plugin family |
| `repository` | SC repository object |
| `netbiosName` | NetBIOS name of the asset |
| `operatingSystem` | Detected OS |
| `macAddress` | MAC address |
| `patchPubDate` | Date the patch was published |
| `pluginPubDate` | Date the plugin was published |
| `pluginText` | Full plugin output text |

---

## Usage examples

### Fetch all vulnerabilities (all severities, table output)

```bash
./sc-vuln
```

### Fetch only Critical and High vulnerabilities

```bash
./sc-vuln --severity 4,3
```

### Filter by plugin text keyword

```bash
# Find all "apache" related vulnerabilities across all severities
./sc-vuln --plugin-text apache

# Critical apache vulnerabilities only
./sc-vuln --plugin-text apache --severity 4
```

### Add extra API filters (append mode — default)

Extra filters are combined with the built-in severity and pluginText filters:

```bash
# Vulns on a specific IP, critical only
./sc-vuln --severity 4 --filter ip=192.168.1.100

# Multiple extra filters
./sc-vuln --severity 4,3 --filter ip=192.168.1.100 --filter port=443
```

### Replace all filters with your own (override mode)

Override mode keeps the severity filter but drops `pluginText` and lets you
fully control what is queried:

```bash
./sc-vuln --filter ip=10.0.0.0/24 --filter-mode override --severity 4,3
```

### Select specific output columns

```bash
./sc-vuln --columns ip,pluginID,name,cvssV3BaseScore,vprScore,exploitAvailable
```

### Output as JSON

```bash
./sc-vuln --severity 4 --format json | jq '.[] | {ip, name, cvssV3BaseScore}'
```

### Output as CSV (pipe to file)

```bash
./sc-vuln \
  --severity 4,3 \
  --plugin-text apache \
  --columns ip,dnsName,pluginID,name,cvssV3BaseScore,solution \
  --format csv \
  > critical_high_apache.csv
```

### Query a specific Security Center when multiple are configured

Pass the SC name as a positional argument. Use a comma-separated list for
multiple SCs. Omit the argument entirely to query all configured SCs.

```bash
# One SC only
./sc-vuln primary --severity 4

# Two SCs, Critical + High
./sc-vuln primary,dr-site --severity 4,3

# All configured SCs (no argument)
./sc-vuln --severity 4
```

### Debug mode to inspect API requests and pagination

```bash
./sc-vuln primary --severity 4 --log-level debug
```

### Full client-side keyword search

The `--full-search-keyword` flag enables client-side search mode. Every
vulnerability record's `pluginText` field is checked against the keywords
listed under `search_keywords` in `config.yaml` (case-insensitive substring
match). Matching records are written to per-severity CSV files.

**1. Add keywords to `config.yaml`:**

```yaml
search_keywords:
  - apache
  - log4j
  - openssl
  - spring
```

**2. Run the search:**

```bash
# Search all severities — produces Critical.csv, High.csv, Medium.csv, Low.csv, Info.csv
./sc-vuln --full-search-keyword /tmp/vuln_results

# Search only Critical and High on a specific SC
./sc-vuln primary --severity 4,3 --full-search-keyword /tmp/vuln_results

# Custom columns in the output CSV
./sc-vuln --severity 4,3 \
  --columns ip,dnsName,pluginID,name,cvssV3BaseScore,solution \
  --full-search-keyword ./scan_$(date +%Y%m%d)
```

**Output files** (one per severity, named with the severity label):

```
/tmp/vuln_results_Critical.csv
/tmp/vuln_results_High.csv
/tmp/vuln_results_Medium.csv
/tmp/vuln_results_Low.csv
/tmp/vuln_results_Info.csv
```

**CSV columns:** the columns you selected + `_matched_keyword` + `_severity` + `_sc`.

**Console progress** (written to stderr, one line per page per SC/severity):

```
[primary/Critical] Page 1 | 1000/8542 records (11.7%) | keywords: apache, log4j
[primary/Critical] Page 2 | 2000/8542 records (23.4%) | keywords: apache, log4j
[dr-site/High]     Page 1 | 500/2301 records (21.7%)  | keywords: apache, log4j
```

> **Note:** CSV files are always flushed and closed even if an error occurs
> mid-search, so partial results are never lost.

### Full example combining multiple options

```bash
./sc-vuln primary \
  --config /etc/sc-vuln/config.yaml \
  --severity 4,3 \
  --plugin-text "ssl" \
  --filter-mode append \
  --filter port=443 \
  --columns ip,dnsName,pluginID,name,severity,cvssV3BaseScore,solution \
  --format csv \
  --log-level info \
  > ssl_vulns_$(date +%Y%m%d).csv
```

---

## Output formats

### table (default)

Human-readable aligned table written to stdout, with a header and separator
row. Suitable for interactive use.

```
_sc        ip            dnsName           pluginID  severity  name               ...
---------  ------------  ----------------  --------  --------  -----------------  ...
primary    10.0.0.1      web01.corp.com    104743    Critical  Apache HTTP Server  ...
primary    10.0.0.2      db01.corp.com     51192     High      SSL Certificate ... ...
```

### json

Pretty-printed JSON array written to stdout. Each element contains all fields
returned by the SC API plus the `_sc` source field.

```bash
./sc-vuln --format json
```

```json
[
  {
    "_sc": "primary",
    "ip": "10.0.0.1",
    "pluginID": "104743",
    "severity": { "id": "4", "name": "Critical" },
    ...
  }
]
```

### csv

RFC 4180 CSV with a header row matching the `--columns` selection.

```bash
./sc-vuln --format csv > results.csv
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `HTTP 403` | Invalid or expired API keys | Regenerate keys in SC → Users → API Keys |
| `HTTP 401` | Wrong `X-ApiKey` header format | Verify `access_key` / `secret_key` in config |
| `certificate signed by unknown authority` | Self-signed SC certificate | Add `skip_tls: true` to the SC entry in config |
| `context deadline exceeded` | SC unreachable or slow | Check network connectivity; use `--timeout 600` to increase the limit |
| Empty results | Filter too restrictive | Run with `--log-level debug` to see the exact filters sent |
| `no security_centers defined` | Config file missing or wrong path | Use `-c /path/to/config.yaml` to specify the path |
