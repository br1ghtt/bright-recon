#!/usr/bin/env bash
# subdomain_enum.sh — Subdomain enumeration + takeover check → feeds recon_scanner.py
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; W='\033[0m'; B='\033[1m'
info()  { echo -e "${C}[*]${W} $*"; }
ok()    { echo -e "${G}[+]${W} $*"; }
warn()  { echo -e "${Y}[!]${W} $*"; }
err()   { echo -e "${R}[-]${W} $*"; }
banner(){ echo -e "\n${B}${C}══════════════════════════════════════════${W}"; \
          echo -e "${B}${C}  $*${W}"; \
          echo -e "${B}${C}══════════════════════════════════════════${W}\n"; }

# ── Input ─────────────────────────────────────────────────────────────────────
if [[ $# -ge 1 ]]; then
    DOMAIN="$1"
else
    read -rp "$(echo -e "${B}Domain:${W} ")" DOMAIN
fi
[[ -z "$DOMAIN" ]] && { err "No domain provided."; exit 1; }

BB_HEADER="${2:-X-Bug-Bounty: antodev}"
THREADS="${3:-50}"
OUTDIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

SUBS_RAW="$OUTDIR/subs_raw.txt"
SUBS_DEDUP="$OUTDIR/subs_dedup.txt"
ALIVE="$OUTDIR/alive.txt"
TAKEOVER="$OUTDIR/takeover.txt"
TARGET="target.txt"          # fed directly into recon_scanner.py

banner "SUBDOMAIN ENUM — $DOMAIN"

# ── Tool checks ───────────────────────────────────────────────────────────────
MISSING=()
for tool in subfinder httpx subzy; do
    command -v "$tool" &>/dev/null || MISSING+=("$tool")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    err "Missing tools: ${MISSING[*]}"
    err "Install via: go install / apt / brew"
    exit 1
fi

# ── Optional tools (silent skip if absent) ────────────────────────────────────
HAS_AMASS=false;  command -v amass   &>/dev/null && HAS_AMASS=true
HAS_ASSETFINDER=false; command -v assetfinder &>/dev/null && HAS_ASSETFINDER=true
HAS_CHAOS=false;  command -v chaos   &>/dev/null && HAS_CHAOS=true
HAS_DNSX=false;   command -v dnsx    &>/dev/null && HAS_DNSX=true
HAS_WAYBACK=false; command -v waybackurls &>/dev/null && HAS_WAYBACK=true

# ── 1. Passive enumeration (all sources → subs_raw.txt) ──────────────────────
info "Subfinder (passive)..."
subfinder -d "$DOMAIN" -silent -all -recursive \
    -o "$OUTDIR/subfinder.txt" 2>/dev/null || true

if $HAS_AMASS; then
    info "Amass (passive)..."
    amass enum -passive -d "$DOMAIN" -silent \
        -o "$OUTDIR/amass.txt" 2>/dev/null || true
fi

if $HAS_ASSETFINDER; then
    info "Assetfinder..."
    assetfinder --subs-only "$DOMAIN" \
        > "$OUTDIR/assetfinder.txt" 2>/dev/null || true
fi

if $HAS_CHAOS; then
    info "Chaos (ProjectDiscovery dataset)..."
    chaos -d "$DOMAIN" -silent \
        -o "$OUTDIR/chaos.txt" 2>/dev/null || true
fi

# ── 2. Merge + deduplicate ────────────────────────────────────────────────────
info "Merging & deduplicating..."
cat "$OUTDIR"/*.txt 2>/dev/null \
    | grep -iE "\.${DOMAIN//./\\.}$" \
    | tr '[:upper:]' '[:lower:]' \
    | sort -u \
    > "$SUBS_DEDUP"

COUNT_SUBS=$(wc -l < "$SUBS_DEDUP")
ok "Unique subdomains found: ${B}${COUNT_SUBS}${W}"
[[ $COUNT_SUBS -eq 0 ]] && { err "No subdomains found. Exiting."; exit 1; }

# ── 3. DNS resolution (dnsx) — optional but speeds up httpx ──────────────────
if $HAS_DNSX; then
    info "DNS resolution with dnsx..."
    dnsx -l "$SUBS_DEDUP" -silent -threads "$THREADS" \
        -o "$SUBS_RAW" 2>/dev/null || cp "$SUBS_DEDUP" "$SUBS_RAW"
else
    cp "$SUBS_DEDUP" "$SUBS_RAW"
fi

# ── 4. HTTP probing (httpx) ───────────────────────────────────────────────────
info "Probing live hosts with httpx..."
httpx \
    -l "$SUBS_RAW" \
    -H "$BB_HEADER" \
    -threads "$THREADS" \
    -timeout 10 \
    -follow-redirects \
    -status-code \
    -content-length \
    -title \
    -tech-detect \
    -no-color \
    -silent \
    -o "$ALIVE" 2>/dev/null || true

COUNT_ALIVE=$(wc -l < "$ALIVE")
ok "Live hosts: ${B}${COUNT_ALIVE}${W}"
[[ $COUNT_ALIVE -eq 0 ]] && { warn "No live hosts detected."; exit 0; }

# ── 5. Subdomain takeover (subzy) ─────────────────────────────────────────────
info "Checking for subdomain takeover (subzy)..."
# Extract bare URLs for subzy (strip httpx metadata)
awk '{print $1}' "$ALIVE" > "$OUTDIR/alive_urls.txt"

subzy run \
    --targets "$OUTDIR/alive_urls.txt" \
    --hide-fails \
    --output "$TAKEOVER" \
    --concurrency "$THREADS" \
    2>/dev/null || true

COUNT_VULN=0
if [[ -f "$TAKEOVER" ]]; then
    COUNT_VULN=$(grep -ic "VULNERABLE" "$TAKEOVER" 2>/dev/null || echo 0)
    [[ $COUNT_VULN -gt 0 ]] && ok "${R}Potential takeovers: ${COUNT_VULN}${W}"
fi

# ── 6. Wayback / JS endpoint harvesting (optional) ───────────────────────────
if $HAS_WAYBACK; then
    info "Wayback URL harvesting..."
    awk '{print $1}' "$ALIVE" \
        | waybackurls 2>/dev/null \
        | grep -iE "\.(json|xml|yaml|env|config|js|bak|log)(\?|$)" \
        | sort -u \
        > "$OUTDIR/wayback_interesting.txt"
    WB_COUNT=$(wc -l < "$OUTDIR/wayback_interesting.txt")
    [[ $WB_COUNT -gt 0 ]] && ok "Interesting Wayback URLs: ${WB_COUNT} → $OUTDIR/wayback_interesting.txt"
fi

# ── 7. Build target.txt for recon_scanner.py ─────────────────────────────────
info "Building target.txt..."

# Live hosts (bare URL only, strip httpx decorations)
awk '{print $1}' "$ALIVE" | sort -u > "$TARGET"

# Append vulnerable takeover hosts (if not already in list)
if [[ -f "$TAKEOVER" ]]; then
    grep -i "VULNERABLE" "$TAKEOVER" \
        | grep -oE 'https?://[^ ]+' \
        | sort -u \
        >> "$TARGET" 2>/dev/null || true
fi

# Final dedup
sort -u "$TARGET" -o "$TARGET"
COUNT_FINAL=$(wc -l < "$TARGET")

# ── 8. Summary ────────────────────────────────────────────────────────────────
banner "DONE"
echo -e "  Output dir    : ${B}$OUTDIR/${W}"
echo -e "  Subdomains    : ${B}$COUNT_SUBS${W}"
echo -e "  Live hosts    : ${B}$COUNT_ALIVE${W}"
echo -e "  Takeovers     : ${B}${R}$COUNT_VULN${W}"
echo -e "  target.txt    : ${B}$COUNT_FINAL entries${W} → ready for recon_scanner.py"
echo ""
ok "Next step:"
echo -e "  ${B}python3 recon_scanner.py -t target.txt${W}"