# Rocket Cheatsheet

Quick reference for all Rocket commands, flags, and common patterns.

---

## Try It — Sample Logs

No logs at hand? Download real-world samples from [LogHub](https://github.com/logpai/loghub):

```bash
# Linux syslog
wget https://raw.githubusercontent.com/logpai/loghub/master/Linux/Syslog/Linux_2k.log

# Apache access logs
wget https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log

# Windows Event Logs (download from LogHub releases)
# Or export from your own machine:
# wevtutil epl Security C:\temp\Security.evtx
```

Then parse them:

```bash
rocket parse Linux_2k.log -o ./output/
rocket parse Apache_2k.log --fields remote_host,method,request_uri,status
```

---

## Core Commands

```
rocket parse       Convert logs to CSV/JSON
rocket stats       Quick triage (no output files)
rocket ioc         Extract IOCs (IPs, hashes, domains, URLs, emails)
rocket timeline    Unified chronological timeline
rocket sigma       Apply Sigma detection rules
rocket geoip       Resolve IP geolocation
rocket tail        Real-time log monitoring
rocket merge       Combine multiple CSVs
rocket formats     List supported formats
rocket version     Build info
```

---

## parse — Convert Logs to CSV/JSON

```bash
# Basic (auto-detect format, output CSV)
rocket parse access.log

# Specify format
rocket parse firewall.log -f keyvalue

# Output JSON instead of CSV
rocket parse firewall.log --output-format json

# Choose output directory
rocket parse access.log -o ./output/

# Directory, recursive
rocket parse /var/log/ -r -o ./results/

# Multiple files
rocket parse server1.log server2.log server3.log

# Compressed .gz (transparent)
rocket parse syslog.2.gz syslog.3.gz

# Windows EVTX
rocket parse Security.evtx -o ./output/

# Merge all results into one file
rocket parse /var/log/ -r --merge -o ./output/

# 8 concurrent workers
rocket parse /evidence/ -r -w 8 --merge
```

---

## Filtering

```bash
# Text filter (case-insensitive)
rocket parse firewall.log --filter "blocked"

# Exclude pattern
rocket parse syslog --exclude "CRON"

# Regex
rocket parse firewall.log --regex 'CVE-\d{4}-\d+'

# Date range
rocket parse /var/log/ -r --date-range 2026-03-01:2026-03-31

# Deduplication
rocket parse firewall.log --dedup
rocket parse firewall.log --dedup --dedup-fields srcip,attack

# Select specific fields only
rocket parse firewall.log --fields srcip,dstip,action,attack

# Combine everything
rocket parse firewall.log \
  --filter "blocked" \
  --exclude "scanner" \
  --regex 'srcip=45\.' \
  --date-range 2026-03-01:2026-03-31 \
  --dedup --dedup-fields srcip,attack \
  --fields srcip,attack,severity
```

---

## Piping (stdin/stdout)

```bash
# Read from stdin
cat /var/log/syslog | rocket parse -f syslog -

# SSH remote pipe
ssh server "cat /var/log/auth.log" | rocket parse -f syslog --filter "Failed" -

# Output to stdout (no file created)
rocket parse firewall.log --output-format json --stdout

# Pipe to jq
rocket parse firewall.log --output-format json --stdout | jq '.srcip'

# Pipe to jq with filter
rocket parse Security.evtx --output-format json --stdout | \
  jq 'select(.event_id == "4625")'

# Pipe to sort/uniq
rocket parse firewall.log --fields srcip --stdout | tail -n +2 | sort | uniq -c | sort -rn

# Import to SQLite
rocket parse firewall.log -o output.csv
sqlite3 analysis.db ".import --csv output.csv logs"
```

---

## stats — Quick Triage

```bash
# All fields
rocket stats access.log

# Specific fields
rocket stats firewall.log --fields srcip,attack,severity --top 15

# Windows EVTX
rocket stats Security.evtx --fields event_id,Event.EventData.TargetUserName

# Syslog services
rocket stats /var/log/syslog --format syslog --fields program --top 20

# Recursive directory
rocket stats /var/log/ -r --fields hostname,program
```

---

## ioc — Extract IOCs

```bash
# All IOC types
rocket ioc firewall.log

# Only IPs and domains
rocket ioc access.log --types ipv4,domain

# Top 30
rocket ioc firewall.log --top 30

# JSON output
rocket ioc /var/log/ -r --output-format json > iocs.json

# From EVTX
rocket ioc Security.evtx --types ipv4,domain

# From stdin
cat syslog | rocket ioc - -f syslog --types ipv4
```

**IOC types:** `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`

---

## timeline — Unified Timeline

```bash
# Multiple sources
rocket timeline Security.evtx syslog firewall.log -o timeline.csv

# JSON timeline (for Splunk/Elastic)
rocket timeline /evidence/ -r --output-format json -o timeline.json

# Filtered timeline
rocket timeline Security.evtx auth.log --filter "failed"

# Select fields
rocket timeline Security.evtx syslog --fields timeline_ts,source,message
```

Each event gets `timeline_ts` (normalized timestamp) and `source` (origin file).

---

## sigma — Sigma Detection Rules

```bash
# Directory of rules
rocket sigma Security.evtx --rules ./sigma-rules/

# Single rule
rocket sigma firewall.log --rules mirai_detection.yml

# JSON output
rocket sigma /var/log/ -r --rules ./rules/ --output-format json -o detections.json

# With syslog format
rocket sigma auth.log --rules brute_force.yml -f syslog
```

**Example rule (save as `detect_rdp.yml`):**

```yaml
title: RDP Logon Detected
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: stable
level: medium
detection:
    selection:
        event_id: '4624'
        Event.EventData.LogonType: '10'
    condition: selection
```

Download community rules: `git clone https://github.com/SigmaHQ/sigma.git`

---

## geoip — IP Geolocation

```bash
# Setup (one time)
mkdir geodb
wget -O geodb/GeoLite2-Country.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
wget -O geodb/GeoLite2-ASN.mmdb \
  "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"

# Resolve IPs
rocket geoip firewall.log --db ./geodb/ --top 20

# Specific IP fields
rocket geoip firewall.log --db ./geodb/ --fields srcip,dstip

# From EVTX
rocket geoip Security.evtx --db ./geodb/
```

---

## tail — Real-time Monitoring

```bash
# Follow mode (like tail -f)
rocket tail /var/log/syslog -f --format syslog

# Filter live
rocket tail /var/log/auth.log -f --filter "fail" --format syslog

# Specific fields
rocket tail /var/log/syslog -f --fields timestamp,program,message --format syslog

# JSON output
rocket tail firewall.log -f --output-format json

# Exclude noise
rocket tail /var/log/syslog -f --exclude "CRON" --format syslog

# Regex live filter
rocket tail access.log -f --regex "5\d{2}"
```

---

## merge — Combine CSVs

```bash
rocket merge file1.csv file2.csv -o merged.csv
rocket merge *.csv -o all_logs.csv
```

Handles different column sets automatically.

---

## Supported Formats

| Format | Description | Example sources |
|---|---|---|
| `keyvalue` | key=value pairs | FortiGate, Palo Alto |
| `json` | JSON Lines / NDJSON | Elasticsearch, Docker |
| `syslog` | BSD, RFC 5424, RFC 3339 | Linux, rsyslog, systemd |
| `cef` | Common Event Format | ArcSight, CrowdStrike |
| `leef` | Log Event Extended Format | IBM QRadar |
| `apache` | Combined/Common Log | Apache, Nginx |
| `w3c` | W3C Extended | IIS, TMG |
| `evtx` | Windows Event Log | Security.evtx, System.evtx |

---

## Incident Response Workflow

```bash
# 1. Collect
scp target:/var/log/syslog* ./evidence/
scp target:/var/log/auth.log* ./evidence/

# 2. Triage
rocket stats ./evidence/ -r --fields program,event_id

# 3. Timeline
rocket timeline ./evidence/ -r -o timeline.csv

# 4. IOCs
rocket ioc ./evidence/ -r --output-format json > iocs.json

# 5. Sigma
rocket sigma ./evidence/ -r --rules ./sigma-rules/ -o detections.json --output-format json

# 6. GeoIP
rocket geoip ./evidence/ -r --db ./geodb/ --top 50

# 7. Export for report
rocket parse ./evidence/ -r --merge -o ./case-report/ --output-format json
```

---

## Common Windows Event IDs

| ID | Description | Hunt for |
|---|---|---|
| 4624 | Logon success | `--filter "4624"` then check LogonType |
| 4625 | Logon failure | Brute force: `--filter "4625"` |
| 4688 | Process created | `--fields Event.EventData.NewProcessName` |
| 4689 | Process exited | Process lifecycle |
| 4672 | Special privileges | Privilege escalation |
| 4720 | User created | Persistence |
| 4732 | User added to group | Privilege escalation |
| 7045 | Service installed | Persistence / malware |
| 1102 | Audit log cleared | Anti-forensics |

```bash
# Hunt for RDP sessions
rocket parse Security.evtx --output-format json --stdout | \
  jq 'select(.event_id == "4624") | select(.["Event.EventData.LogonType"] == "10")'

# Hunt for suspicious processes
rocket parse Security.evtx --output-format json --stdout | \
  jq 'select(.event_id == "4688") | .["Event.EventData.NewProcessName"]' | \
  sort | uniq -c | sort -rn | head -20
```

---

## Performance Reference

| Source | Records | Time |
|---|---|---|
| FortiAnalyzer (5.5 MB) | 5,914 | 0.21s |
| Syslog (2.9 MB, 3 .gz) | 61,215 | 0.12s |
| Windows EVTX (51 MB) | 113,030 | 5.3s |

---

Developed by Hernan Herrera - Sockets AR
https://rocket.sockets.ar
