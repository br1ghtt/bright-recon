# bright-recon
# subdomain-enum

A modular Bash pipeline for passive subdomain enumeration, DNS resolution, HTTP probing, and takeover checks.

## Prerequisites

Required:
- subfinder
- httpx
- subzy

Optional (auto-detected, used if present):
- amass
- assetfinder
- chaos
- dnsx
- waybackurls

## Installation

```bash
git clone https://github.com/your-username/subdomain-enum.git
cd subdomain-enum
chmod +x subdomain.sh
```

## Usage

```bash
./subdomain.sh <domain> [bug-bounty-header] [threads]
```

Example:

```bash
./subdomain.sh example.com "X-Bug-Bounty: h1_username" 30
```

## Output

Creates `recon_<domain>_<timestamp>/` with:
- `subs_dedup.txt` — unique subdomains
- `alive.txt` — live hosts (httpx)
- `takeover.txt` — subzy takeover results
- `wayback_interesting.txt` — interesting archived URLs (if waybackurls present)

Also generates `target.txt` in the current directory, ready for `recon_scanner.py`:

```bash
python3 recon_scanner.py -t target.txt
```
