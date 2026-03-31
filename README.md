# Rocket

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat)](https://github.com/hernannh/rocket/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat)](LICENSE)
[![Static Binary](https://img.shields.io/badge/Binary-Static%20%7C%204.5MB-green?style=flat)](https://github.com/hernannh/rocket/releases)
[![Log Formats](https://img.shields.io/badge/Log%20Formats-11-00d4ff?style=flat)](#supported-log-formats)
[![Sigma Rules](https://img.shields.io/badge/Sigma-Rules%20Engine-blueviolet?style=flat)](#sigma)
[![GeoIP](https://img.shields.io/badge/GeoIP-MaxMind%20GeoLite2-orange?style=flat)](#geoip)

**Blue Team Log Analysis Toolkit** — Convert any log format to structured CSV or JSON in seconds. A single static binary that parses, filters, correlates, and enriches logs from firewalls, SIEM, Windows EVTX, syslog, DNS, and more.

Rocket was built for SOC analysts, incident responders, and forensic investigators who need to process logs fast, on any machine, without installing dependencies.

---

### SSH Brute Force Analysis

![Rocket SSH Analysis](demo/rocket-ssh-analysis.gif)

### FortiGate IPS Analysis

![Rocket FortiGate Analysis](demo/rocket-fortigate-analysis.gif)

### Nginx Web Server Analysis

![Rocket Nginx Analysis](demo/rocket-nginx-analysis.gif)

---

## Why Rocket?

- **CSV & JSON export** — Convert any log format to structured CSV (Excel, databases) or JSON Lines (jq, Splunk, Elasticsearch). Select specific fields with `--fields` to reduce noise. The core value of Rocket.
- **Single static binary** (4.5 MB) — Copy it to any machine via SCP and run. No Python, no Java, no runtime. Works on forensic workstations, compromised servers, air-gapped systems.
- **11 log formats** with auto-detection — keyvalue, json, syslog, cef, leef, apache, w3c, nginx-error, bind9, android, and Windows EVTX (native binary parsing). Reads `.gz` compressed files transparently.
- **Advanced filtering** — Text search, exclusion, regex, date ranges, deduplication. Pipe from stdin, output to stdout. Combine filters freely.
- **Streaming I/O** — Handles multi-GB log files without loading them into memory. 500K+ records/second on syslog. Concurrent processing with configurable workers.
- **Built-in threat intelligence** — IOC extraction, Sigma rule engine, GeoIP resolution, and timeline builder in a single tool. No need for separate scripts.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Supported Log Formats](#supported-log-formats)
- [Commands](#commands)
  - [parse](#parse) — Convert logs to CSV/JSON
  - [stats](#stats) — Quick triage and field analysis
  - [ioc](#ioc) — Extract Indicators of Compromise
  - [timeline](#timeline) — Unified chronological timeline
  - [sigma](#sigma) — Sigma detection rules engine
  - [geoip](#geoip) — IP geolocation with GeoLite2
  - [tail](#tail) — Real-time log monitoring
  - [merge](#merge) — Combine multiple CSV files
  - [formats](#formats) — List supported formats
  - [version](#version) — Build information
- [Filtering](#filtering)
- [Output Formats](#output-formats)
- [Use Cases](#use-cases)
- [Performance](#performance)
- [GeoIP Database Setup](#geoip-database-setup)
- [Sigma Rules](#sigma-rules)
- [Platform Support](#platform-support)

---

## Installation

Download the binary for your platform from the [Releases](https://github.com/hernannh/rocket/releases) page.

### Linux (amd64)

```bash
chmod +x rocket-linux-amd64
sudo mv rocket-linux-amd64 /usr/local/bin/rocket
```

### macOS

```bash
chmod +x rocket-darwin-arm64
sudo mv rocket-darwin-arm64 /usr/local/bin/rocket
```

### Windows

Download `rocket-windows-amd64.exe` and add it to your PATH, or run it directly.

### Verify installation

```bash
rocket version
```

---

## Quick Start

```bash
# Parse a single log file (auto-detects format)
rocket parse access.log

# Parse a directory recursively and merge all results
rocket parse /var/log/ -r --merge -o ./output/

# Quick triage — top IPs, events, users
rocket stats Security.evtx --fields event_id,Event.EventData.TargetUserName --top 15

# Extract IOCs (IPs, domains, hashes, URLs)
rocket ioc firewall.log --top 20

# Build a timeline from multiple sources
rocket timeline Security.evtx syslog firewall.log -o timeline.csv

# Apply Sigma detection rules
rocket sigma Security.evtx --rules ./sigma-rules/

# Resolve GeoIP for attacker IPs
rocket geoip firewall.log --db ./geodb/ --top 20

# Monitor a log file in real-time
rocket tail /var/log/syslog -f --filter "fail" --format syslog
```

---

## Supported Log Formats

| Format | Description | Auto-detect | Examples |
|---|---|---|---|
| **keyvalue** | Key=value pairs | Yes | FortiGate, FortiAnalyzer, Palo Alto, generic app logs |
| **json** | JSON Lines / NDJSON | Yes | Elasticsearch, CloudWatch, Docker, structured app logs |
| **syslog** | BSD, RFC 5424, RFC 3339 | Yes | Linux syslog, rsyslog, systemd-journal, network devices |
| **cef** | ArcSight Common Event Format | Yes | ArcSight, FortiSIEM, CrowdStrike, any CEF-compliant source |
| **leef** | IBM QRadar LEEF 1.0/2.0 | Yes | QRadar, IBM Security products |
| **apache** | Combined and Common Log Format | Yes | Apache, Nginx (with common log format), HAProxy |
| **w3c** | W3C Extended Log Format | Yes | IIS, Microsoft TMG, some CDN providers |
| **nginx-error** | Nginx error log format | Yes | Nginx error logs with client/server extraction |
| **bind9** | BIND9 DNS server logs | Yes | DNS query logs and security logs |
| **android** | Android logcat (threadtime) | Yes | Android system and application logs |
| **evtx** | Windows Event Log (binary) | By extension | Security.evtx, System.evtx, Application.evtx |

### Format auto-detection

Rocket samples the first 20 lines of each file and scores them against all registered parsers. The parser with the highest confidence score is selected. For EVTX files, detection is based on the `.evtx` file extension.

You can force a specific format with `--format` / `-f`:

```bash
rocket parse mixed.log --format syslog
rocket parse data.txt -f keyvalue
```

---

## Commands

### parse

Convert one or more log files to CSV or JSON format.

```
rocket parse <input> [flags]
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--output` | `-o` | Output directory (default: same as input) |
| `--format` | `-f` | Log format: auto, keyvalue, json, syslog, cef, leef, apache, w3c, nginx-error, bind9, android, evtx (default: auto) |
| `--output-format` | | Output format: csv, json (default: csv) |
| `--filter` | | Keep only lines containing this text (case-insensitive) |
| `--exclude` | | Exclude lines containing this text (case-insensitive) |
| `--regex` | | Keep only lines matching this regex pattern |
| `--fields` | | Comma-separated list of fields to include in output |
| `--date-range` | | Date range filter: YYYY-MM-DD:YYYY-MM-DD |
| `--dedup` | | Remove duplicate records |
| `--dedup-fields` | | Fields to use for dedup (default: full line) |
| `--recursive` | `-r` | Scan subdirectories recursively |
| `--merge` | | Merge all outputs into a single file |
| `--workers` | `-w` | Number of concurrent workers (default: 4) |
| `--stdout` | | Write output to stdout instead of files |

**Examples:**

```bash
# Basic conversion
rocket parse access.log
rocket parse /var/log/app/ -r -o ./output/

# Filter and field selection
rocket parse firewall.log --filter "blocked" --fields srcip,dstip,action,attack
rocket parse syslog --exclude "CRON" --fields timestamp,program,message

# Regex filtering
rocket parse firewall.log --regex 'CVE-\d{4}-\d+'
rocket parse auth.log --regex 'Failed password.*from \d+\.\d+'

# Date range
rocket parse /var/log/ -r --date-range 2026-03-01:2026-03-31

# JSON output piped to jq
rocket parse firewall.log --output-format json --stdout | jq '.srcip'

# Deduplication
rocket parse firewall.log --dedup --dedup-fields srcip,attack

# Windows Event Logs
rocket parse Security.evtx -o ./output/
rocket parse C:\Windows\System32\winevt\Logs\ -r --merge

# DNS logs
rocket parse query.log -f bind9 --fields client_ip,domain,record_type

# Multiple inputs
rocket parse server1.log server2.log server3.log -o ./merged/ --merge

# Read from stdin (pipe)
cat /var/log/syslog | rocket parse -f syslog --fields program,message -
ssh forensic-server "cat /var/log/auth.log" | rocket parse -f syslog --filter "Failed" -

# Compressed files (.gz)
rocket parse /var/log/syslog.2.gz /var/log/syslog.3.gz -o ./output/

# High-performance batch processing
rocket parse /evidence/logs/ -r --workers 8 --merge -o ./case-output/
```

**Supported input types:**
- Single file: `rocket parse access.log`
- Multiple files: `rocket parse file1.log file2.log file3.log`
- Directory: `rocket parse /var/log/`
- Directory (recursive): `rocket parse /var/log/ -r`
- Glob pattern: `rocket parse "*.log"`
- Gzip compressed: `rocket parse syslog.2.gz`
- Stdin: `cat file | rocket parse -f syslog -`

---

### stats

Quick triage — analyze log files and display top values per field without generating output files.

```
rocket stats <input> [flags]
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--format` | `-f` | Log format (default: auto) |
| `--fields` | | Comma-separated fields to analyze (default: all) |
| `--top` | | Number of top values per field (default: 10) |
| `--recursive` | `-r` | Scan subdirectories |

**Examples:**

```bash
# Overview of all fields
rocket stats access.log

# Focus on specific fields
rocket stats firewall.log --fields srcip,attack,severity,srccountry --top 15

# Windows Event Log triage
rocket stats Security.evtx --fields event_id,Event.EventData.TargetUserName,Event.EventData.LogonType

# DNS query analysis
rocket stats query.log --fields domain,record_type,client_ip --top 20

# Syslog service analysis
rocket stats /var/log/syslog -r --format syslog --fields program,hostname --top 20
```

**Example output:**

```
=== Summary ===
Total records: 613
Unique fields: 4

--- attack (19 unique values) ---
       186  Mirai.Botnet
       134  ZGrab.Scanner
        75  Nmap.Script.Scanner
        33  Apache.HTTP.Server.cgi-bin.Path.Traversal
        32  WordPress.REST.API.Username.Enumeration.Information.Disclosure
  ... and 14 more

--- srcip (351 unique values) ---
        18  45.205.1.20
        15  172.233.29.203
        15  20.43.23.11
  ... and 346 more
```

---

### ioc

Extract Indicators of Compromise (IOCs) from log files.

```
rocket ioc <input> [flags]
```

**Supported IOC types:**

| Type | Description | Example |
|---|---|---|
| `ipv4` | IPv4 addresses (public only) | `45.205.1.20` |
| `ipv6` | IPv6 addresses | `2001:db8::1` |
| `domain` | Domain names | `evil.example.com` |
| `url` | HTTP/HTTPS URLs | `https://malware.site/payload` |
| `email` | Email addresses | `attacker@evil.com` |
| `md5` | MD5 hashes (32 hex chars) | `d41d8cd98f00b204e9800998ecf8427e` |
| `sha1` | SHA1 hashes (40 hex chars) | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `sha256` | SHA256 hashes (64 hex chars) | `e3b0c44298fc1c149afbf4c8996fb924...` |

Private/reserved IP ranges (10.x, 172.16.x, 192.168.x, 127.x) are automatically excluded.

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--format` | `-f` | Log format (default: auto) |
| `--types` | | Comma-separated IOC types to extract (default: all) |
| `--output-format` | | Output: text, json (default: text) |
| `--top` | | Number of top IOCs per type (default: 20) |
| `--recursive` | `-r` | Scan subdirectories |

**Examples:**

```bash
# Extract all IOCs
rocket ioc firewall.log

# Only IPs and domains
rocket ioc access.log --types ipv4,domain --top 30

# JSON output for integration with other tools
rocket ioc /var/log/ -r --output-format json > iocs.json

# From EVTX
rocket ioc Security.evtx --types ipv4,domain

# From stdin
cat syslog | rocket ioc - -f syslog --types ipv4
```

---

### timeline

Build a unified chronological timeline from multiple log sources. Essential for incident reconstruction.

```
rocket timeline <input> [inputs...] [flags]
```

Each event is enriched with:
- `timeline_ts` — Normalized timestamp for sorting
- `source` — Original file path

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--output` | `-o` | Output file path (default: timeline.csv) |
| `--format` | `-f` | Log format (default: auto per file) |
| `--output-format` | | Output: csv, json (default: csv) |
| `--fields` | | Comma-separated fields to include |
| `--filter` | | Keep only lines containing this text |
| `--exclude` | | Exclude lines containing this text |
| `--recursive` | `-r` | Scan subdirectories |

**Examples:**

```bash
# Combine Windows + Linux + Firewall logs
rocket timeline Security.evtx syslog firewall.log -o timeline.csv

# JSON timeline for Elastic/Splunk ingestion
rocket timeline /evidence/ -r --output-format json -o timeline.json

# Filtered timeline
rocket timeline Security.evtx auth.log --filter "failed" --fields timeline_ts,source,message
```

---

### sigma

Apply Sigma detection rules against parsed log records. Sigma is the open standard for SIEM detection rules used by the cybersecurity community.

```
rocket sigma <input> [flags]
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--rules` | | Path to Sigma rules directory or single .yml file **(required)** |
| `--format` | `-f` | Log format (default: auto) |
| `--output-format` | | Output: text, json (default: text) |
| `--output` | `-o` | Output file (default: stdout) |
| `--recursive` | `-r` | Scan subdirectories |

**Supported Sigma features:**

| Feature | Support |
|---|---|
| Field matching (exact) | Yes |
| Field modifiers: `contains`, `startswith`, `endswith` | Yes |
| Wildcard matching (`*`) | Yes |
| Conditions: `and`, `or`, `not` | Yes |
| Conditions: `1 of them`, `all of them` | Yes |
| Conditions: `1 of selection_*`, `all of selection_*` | Yes |
| Keyword lists (match all fields) | Yes |
| Parentheses in conditions | Yes |

**Examples:**

```bash
# Scan with a directory of rules
rocket sigma Security.evtx --rules ./sigma-rules/

# Single rule
rocket sigma firewall.log --rules mirai_detection.yml

# JSON output for further processing
rocket sigma /var/log/ -r --rules ./rules/ --output-format json -o detections.json

# Combine with syslog
rocket sigma auth.log --rules brute_force.yml --format syslog
```

**Example Sigma rule:**

```yaml
title: Mirai Botnet Detection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
level: critical
description: Detects Mirai botnet activity in IPS logs
logsource:
    category: ids
    product: fortigate
detection:
    selection:
        attack|contains: Mirai
    condition: selection
```

**Example Sigma rule for Windows:**

```yaml
title: Remote Desktop Logon Detected
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: stable
level: medium
description: Detects RDP logon events (LogonType 10)
logsource:
    product: windows
    service: security
detection:
    selection:
        event_id: '4624'
        Event.EventData.LogonType: '10'
    condition: selection
```

You can use rules from the [SigmaHQ](https://github.com/SigmaHQ/sigma) community repository.

---

### geoip

Resolve geolocation data (country, ASN, organization) for IP addresses found in log files.

```
rocket geoip <input> [flags]
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--db` | | Path to mmdb file or directory with mmdb files **(required)** |
| `--format` | `-f` | Log format (default: auto) |
| `--fields` | | Fields to scan for IPs (default: all) |
| `--top` | | Number of top IPs to show (default: 20) |
| `--recursive` | `-r` | Scan subdirectories |

**Examples:**

```bash
# Basic geolocation
rocket geoip firewall.log --db ./GeoLite2-Country.mmdb

# Multiple databases (directory)
rocket geoip firewall.log --db ./geodb/ --top 30

# Focus on specific IP fields
rocket geoip firewall.log --db ./geodb/ --fields srcip,dstip

# EVTX files
rocket geoip Security.evtx --db ./geodb/
```

**Example output:**

```
=== GeoIP Resolution (160 unique public IPs) ===

COUNT     IP                  CC   COUNTRY                 ASN       ORGANIZATION
--------  ------------------  ---  ----------------------  --------  ------------
43        172.93.48.52        US   United States           29802     HIVELOCITY, Inc.
22        87.251.64.141       US   United States           200730    ISAEV Igor
20        45.161.237.218      PY   Paraguay                61512     GIG@NET SOCIEDAD ANONIMA
15        89.168.34.129       FR   France                  31898     Oracle Corporation
15        103.76.120.225      ID   Indonesia               136052    PT Cloud Hosting Indonesia

=== Events by Country ===

       161  United States
       106  China
        74  Romania
        61  Hong Kong
        60  Indonesia
```

See [GeoIP Database Setup](#geoip-database-setup) for download instructions.

---

### tail

Monitor a log file in real-time with structured parsing, filtering, and formatting. Like `tail -f` but with intelligence.

```
rocket tail <file> [flags]
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--follow` | `-f` | Follow file for new lines (like tail -f) |
| `--format` | | Log format (default: auto) |
| `--filter` | | Keep only lines containing this text |
| `--exclude` | | Exclude lines containing this text |
| `--regex` | | Keep only lines matching this regex |
| `--fields` | | Comma-separated fields to display |
| `--output-format` | | Output: text, json, csv (default: text) |

**Examples:**

```bash
# Real-time monitoring
rocket tail /var/log/syslog -f --format syslog

# Filter for failures
rocket tail /var/log/auth.log -f --filter "fail" --format syslog

# Show specific fields
rocket tail /var/log/syslog -f --fields timestamp,program,message --format syslog

# JSON output for piping
rocket tail firewall.log -f --output-format json --fields srcip,action

# Exclude noise
rocket tail /var/log/syslog -f --exclude "CRON" --format syslog
```

---

### merge

Combine multiple CSV files into a single unified CSV. Handles files with different column sets by creating a union of all headers.

```
rocket merge <file1.csv> <file2.csv> [files...] [flags]
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--output` | `-o` | Output file path (default: merged_logs.csv) |

**Examples:**

```bash
rocket merge output1.csv output2.csv -o merged.csv
rocket merge *.csv -o all_logs.csv
```

---

### formats

List all supported log formats.

```bash
rocket formats
```

**Output:**

```
FORMAT       DESCRIPTION
------       -----------
keyvalue     Key=value pairs (e.g., user=admin action=login status="ok")
json         JSON lines / NDJSON (one JSON object per line)
syslog       Syslog (BSD, RFC 5424, and RFC 3339/rsyslog formats)
cef          ArcSight Common Event Format (CEF)
leef         IBM QRadar Log Event Extended Format (LEEF 1.0/2.0)
apache       Apache access logs (Combined and Common Log Format)
w3c          W3C Extended Log File Format (IIS, proxies)
nginx-error  Nginx error log format
bind9        BIND9 DNS server logs (query and security)
android      Android logcat (threadtime format)
evtx         Windows Event Log (.evtx) — Security, System, Application
```

---

### version

Show build information.

```bash
rocket version
```

```
rocket v1.0.0
  commit:  a1b2c3d
  built:   2026-03-31T00:00:00Z
  go:      go1.22.0
  os/arch: linux/amd64
```

---

## Filtering

Rocket provides multiple filtering mechanisms that can be combined:

| Filter | Flag | Description |
|---|---|---|
| Text (include) | `--filter "ERROR"` | Case-insensitive substring match |
| Text (exclude) | `--exclude "CRON"` | Case-insensitive substring exclusion |
| Regex | `--regex 'CVE-\d{4}-\d+'` | Full regex pattern matching |
| Date range | `--date-range 2026-03-01:2026-03-31` | ISO date range (inclusive) |
| Dedup | `--dedup` | Remove exact duplicate lines |
| Dedup by fields | `--dedup --dedup-fields srcip,attack` | Dedup by specific field combination |
| Field selection | `--fields srcip,attack,severity` | Only include these columns in output |

**Filters can be combined:**

```bash
rocket parse firewall.log \
  --filter "blocked" \
  --exclude "scanner" \
  --regex 'srcip=45\.' \
  --date-range 2026-03-01:2026-03-31 \
  --dedup --dedup-fields srcip,attack \
  --fields srcip,attack,severity,srccountry
```

---

## Output Formats

### CSV (default)

Standard CSV with headers. Compatible with Excel, Google Sheets, LibreOffice, pandas, databases.

```bash
rocket parse firewall.log -o ./output/
```

### JSON Lines (NDJSON)

One JSON object per line. Compatible with `jq`, Splunk, Elasticsearch, Logstash, custom scripts.

```bash
rocket parse firewall.log --output-format json -o ./output/
```

### Pipe to jq

```bash
rocket parse firewall.log --output-format json --stdout | jq 'select(.severity == "critical")'
rocket parse firewall.log --output-format json --stdout | jq -r '.srcip' | sort -u
rocket parse Security.evtx --output-format json --stdout | jq 'select(.event_id == "4625")'
```

### Pipe to other tools

```bash
# Count unique IPs
rocket parse firewall.log --fields srcip --stdout | tail -n +2 | sort -u | wc -l

# Feed to grep
rocket parse firewall.log --output-format json --stdout | grep "Mirai"

# Import to SQLite
rocket parse firewall.log -o output.csv
sqlite3 analysis.db ".import --csv output.csv logs"
```

---

## Use Cases

### Incident Response

```bash
# 1. Collect evidence from multiple sources
scp target:/var/log/syslog* ./evidence/
scp target:/var/log/auth.log* ./evidence/
# Copy EVTX from Windows (via WinSCP, forensic image, etc.)

# 2. Build a unified timeline
rocket timeline ./evidence/ -r -o timeline.csv

# 3. Quick triage
rocket stats ./evidence/ -r --fields program,hostname,event_id

# 4. Extract IOCs
rocket ioc ./evidence/ -r --output-format json > iocs.json

# 5. Apply Sigma detection rules
rocket sigma ./evidence/ -r --rules ./sigma-rules/ --output-format json > detections.json

# 6. GeoIP resolution on attacker IPs
rocket geoip ./evidence/ -r --db ./geodb/ --top 50
```

### Threat Hunting

```bash
# Find lateral movement (RDP sessions)
rocket parse Security.evtx --output-format json --stdout | \
  jq 'select(.event_id == "4624") | select(.["Event.EventData.LogonType"] == "10")'

# Hunt for path traversal attacks
rocket parse firewall.log --regex '\.\./|%2e%2e' --fields srcip,url,attack

# Find brute force patterns
rocket parse auth.log -f syslog --filter "Failed password" --fields timestamp,message

# Analyze DNS queries for suspicious domains
rocket stats query.log -f bind9 --fields domain,client_ip --top 20

# Extract all CVEs being exploited
rocket parse firewall.log --regex 'CVE-\d{4}-\d+' --fields srcip,attack,cve --output-format json --stdout | \
  jq -r '.cve' | sort | uniq -c | sort -rn
```

### SOC Daily Operations

```bash
# Morning triage — what happened overnight
rocket stats /var/log/fortigate.log --fields attack,severity,srcip --top 10

# Real-time monitoring during incident
rocket tail /var/log/syslog -f --filter "fail" --format syslog --fields timestamp,program,message

# Process FortiAnalyzer export
rocket parse ./forti-export/ -r --merge -o ./daily-report/ --workers 8

# Filter out known false positives
rocket parse firewall.log --exclude "scanner" --exclude "monitor" --fields srcip,attack,severity
```

### Forensic Analysis

```bash
# Process Windows Event Logs from disk image
rocket parse /mnt/evidence/Windows/System32/winevt/Logs/ -r -o ./case-42/

# Focus on security-relevant events
rocket parse Security.evtx --output-format json --stdout | \
  jq 'select(.event_id == "4688")' | \  # Process creation
  jq 'select(.["Event.EventData.NewProcessName"] | test("powershell|cmd|wscript"))'

# Decompress and process rotated logs
rocket parse /mnt/evidence/var/log/syslog* /mnt/evidence/var/log/auth.log* -o ./case-42/
```

---

## Performance

Benchmarks from real-world log files:

| Source | Size | Records | Time | Throughput |
|---|---|---|---|---|
| FortiAnalyzer (3 files) | 5.5 MB | 5,914 | 0.21s | 28,162 records/s |
| Linux syslog (5 files, 3 .gz) | 2.9 MB | 61,215 | 0.12s | 510,125 records/s |
| Windows EVTX (3 files) | 51 MB | 113,030 | 5.3s | 21,325 records/s |
| BIND9 DNS (2 files) | 19 MB | 144,089 | 1.2s | 120,074 records/s |
| Nginx (18 files, 9 .gz) | 4.8 MB | 17,703 | 0.08s | 221,288 records/s |
| Timeline (EVTX + syslog + FW) | Mixed | 33,245 | 2.1s | 15,831 records/s |

- Concurrent processing scales with available CPU cores (configurable with `--workers`)
- Gzip files are decompressed on-the-fly with zero disk overhead
- Memory usage stays constant regardless of file size (streaming I/O)

---

## GeoIP Database Setup

Rocket uses MaxMind GeoLite2 databases in MMDB format. These are free and updated regularly.

### Download databases

```bash
mkdir -p geodb
wget -O geodb/GeoLite2-Country.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
wget -O geodb/GeoLite2-ASN.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
wget -O geodb/GeoLite2-City.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
```

### Usage

```bash
# Point to directory (auto-detects database types)
rocket geoip firewall.log --db ./geodb/

# Point to single file
rocket geoip firewall.log --db ./geodb/GeoLite2-Country.mmdb
```

The `--db` flag accepts:
- A directory containing `.mmdb` files (auto-detects Country, ASN, City by filename)
- A single `.mmdb` file

---

## Sigma Rules

### What is Sigma?

[Sigma](https://github.com/SigmaHQ/sigma) is an open standard for writing detection rules that can be shared across SIEM systems. Rocket includes a built-in Sigma engine that evaluates rules directly against parsed log records.

### Using community rules

```bash
# Clone the SigmaHQ repository
git clone https://github.com/SigmaHQ/sigma.git

# Scan Windows logs against Windows rules
rocket sigma Security.evtx --rules ./sigma/rules/windows/

# Scan web logs against web rules
rocket sigma access.log --rules ./sigma/rules/web/
```

### Writing custom rules

Create a `.yml` file following the Sigma specification:

```yaml
title: Brute Force SSH Detection
id: unique-uuid-here
status: stable
level: high
description: Detects multiple failed SSH login attempts
logsource:
    product: linux
    service: auth
detection:
    selection:
        program: sshd
        message|contains: "Failed password"
    condition: selection
```

```bash
rocket sigma /var/log/auth.log --rules brute_force_ssh.yml -f syslog
```

---

## Platform Support

| Platform | Architecture | Binary |
|---|---|---|
| Linux | amd64 | `rocket-linux-amd64` |
| Linux | arm64 | `rocket-linux-arm64` |
| Windows | amd64 | `rocket-windows-amd64.exe` |
| macOS | amd64 (Intel) | `rocket-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `rocket-darwin-arm64` |

All binaries are:
- Statically linked (no shared library dependencies)
- Compiled with `CGO_ENABLED=0` (pure Go)
- Stripped of debug symbols (`-s -w`)
- Ready to run on any machine with no installation

---

## License

Licensed under the [Apache License 2.0](LICENSE). You are free to use, modify, and distribute this software. Attribution to the original author is required.

---

Developed by Hernan Herrera - [Sockets AR](https://sockets.ar)

Website: [rocket.sockets.ar](https://rocket.sockets.ar)
