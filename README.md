# UFH NetEng Tenable

A command-line tool for pulling network-equipment vulnerability data from **Tenable Vulnerability Management** (cloud.tenable.com) and turning it into CSV/Excel reports and terminal summaries. It's a faster alternative to the web dashboard.

## How it works

1. **`pull`** uses Tenable's **bulk export API** (via the official [pyTenable](https://github.com/tenable/pyTenable) SDK). Tenable builds the dataset server-side in chunks, and pyTenable downloads them, polls for completion, and backs off on rate limits. This is much faster than paging through the UI.
2. The raw JSON is cached in `cache/`. Every other command reads from that cache, so you can run as many reports or lookups as you like without calling the API again.
3. Records are flattened into a pandas DataFrame with one row per finding (device × plugin × port). The tool then rolls them up by device, plugin, CVE, and vendor/OS.

The tool sees exactly what your API key's account can see. If your account is scoped to network equipment, every report covers only network equipment, so you don't need a filter.

## Setup

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
pip install -r requirements.txt
```

```bash
cp .env.example .env
```

Put your keys in `.env` (Tenable: **Settings → My Account → API Keys**). `.env` is in `.gitignore`, so it won't be committed. You can also export `TIO_ACCESS_KEY` and `TIO_SECRET_KEY` as environment variables instead.

## Usage

```bash
# 1. Pull open + reopened findings, low severity and above (the default)
python -m tenable_net pull

# Narrow the pull
python -m tenable_net pull --severity critical high --since 30
python -m tenable_net pull --state open reopened fixed --plugin-output

# 2. Terminal overview: severity totals, worst devices, top plugins, vendor/OS breakdown
python -m tenable_net summary --top 25

# 3. Excel + CSV reports (output/<timestamp>/)
python -m tenable_net report
python -m tenable_net report --out reports/weekly --no-xlsx

# 4. Look up one device (hostname substring or exact IP)
python -m tenable_net device core-sw-01
python -m tenable_net device 10.0.0.1

# 5. Which devices are affected by a CVE, plugin ID, or plugin-name text?
python -m tenable_net search CVE-2023-20198
python -m tenable_net search 180001
python -m tenable_net search "snmp"
```

Add `--refresh` to `summary`, `report`, `device`, or `search` to pull fresh data first. Add `--include-info` to include informational findings, which are excluded by default. Run any command with `-h` to see its options.

### Excel workbook sheets

| Sheet | Contents |
|---|---|
| Severity Summary | Number of findings and affected devices for each severity |
| By Device | Critical/high/medium/low counts, max VPR, exploitable count, and last seen for each device |
| By Plugin | Each plugin with its affected device count, max VPR, CVSSv3, CVEs, and solution |
| By CVE | Each CVE with its affected device count and related plugins |
| By Vendor-OS | Roll-up by vendor (Cisco, Juniper, Palo Alto, …) and OS version |
| Findings | Every finding, with synopsis, solution, port, and first/last found |
| Assets | Asset inventory from the asset export, including devices that have no findings |

Every sheet has a frozen header row and auto-filters.

## Development

```bash
pip install pytest
```

```bash
python -m pytest -q
```

The tests run against sample export records in `tests/fixtures/` and don't need API access.

## Layout

```
tenable_net/
  client.py      TenableIO client built from env / .env
  export.py      bulk vuln + asset exports, JSON cache
  normalize.py   flatten export records into DataFrames; vendor detection
  reports.py     rollups + CSV/XLSX writer
  summaries.py   rich terminal tables, device/search lookups
  cli.py         argparse entrypoint
```
