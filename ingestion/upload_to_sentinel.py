#!/usr/bin/env python3
"""Push the prepared WAF logs into Microsoft Sentinel via the Azure Monitor Logs
Ingestion API (DCR-based).

Reads the prepared log files READ-ONLY, parses them into rows matching the
WAFAudit_CL / WAFAccess_CL schemas, and uploads them through a Data Collection
Rule.

Configuration:
  - Secrets come ONLY from environment variables:
        AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
  - Non-secret-but-identifying values also come from the environment (the
    placeholders below are intentional — set the real DCE URL / DCR immutable ID
    in your shell, never commit them):
        DCE_ENDPOINT, DCR_IMMUTABLE_ID
  - The prepared input logs (produced by the dissertation pipeline) are read from
    WAF_INPUT_DIR (defaults to this script's folder) and are NOT committed here.

Usage:
    python upload_to_sentinel.py --dry-run     # parse + report, send nothing
    python upload_to_sentinel.py               # real upload (needs env vars)
"""
import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# ----------------------------------------------------------------------------
# Configuration — all environment-driven (placeholders shown for the portfolio).
# ----------------------------------------------------------------------------
DCE_ENDPOINT = os.environ.get("DCE_ENDPOINT", "<DCE_ENDPOINT>")
DCR_IMMUTABLE_ID = os.environ.get("DCR_IMMUTABLE_ID", "<DCR_IMMUTABLE_ID>")
AUDIT_STREAM = os.environ.get("AUDIT_STREAM", "Custom-WAFAudit_CL")
ACCESS_STREAM = os.environ.get("ACCESS_STREAM", "Custom-WAFAccess_CL")

BATCH_SIZE = 500          # rows per upload call (SDK still chunks to <1MB internally)
SEARCH_ENDPOINT = "/rest/products/search"

# Prepared log files live alongside this script by default; override with WAF_INPUT_DIR.
SI = Path(os.environ.get("WAF_INPUT_DIR", Path(__file__).resolve().parent))

# (filename, kind, paranoia_level, stream)
FILES = [
    ("pl1_audit.log",            "audit",  1, AUDIT_STREAM),
    ("pl2_audit.log",            "audit",  2, AUDIT_STREAM),
    ("pl1_access_filtered.log",  "access", 1, ACCESS_STREAM),
    ("pl2_access_filtered.log",  "access", 2, ACCESS_STREAM),
]

# ----------------------------------------------------------------------------
# Parsing helpers (identical logic to the sample-generation step)
# ----------------------------------------------------------------------------
def iso_from_asctime(ts: str) -> str:
    # "Mon Apr  6 23:59:38 2026" (asctime; double space before single-digit day)
    dt = datetime.strptime(" ".join(ts.split()), "%a %b %d %H:%M:%S %Y")
    return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_nginx(ts: str) -> str:
    # "06/Apr/2026:23:59:38 +0000"
    dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def attack_cat(rule_id: str) -> str:
    if rule_id.startswith("942"):
        return "SQLi"
    if rule_id.startswith("941"):
        return "XSS"
    return "Other"


ACCESS_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (.*?) (\S+)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
)


def parse_audit(path: Path, paranoia: int):
    """Return (rows, skipped_counter, total_lines, search_count)."""
    rows, skipped = [], Counter()
    total = search = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total += 1
            line = line.strip()
            if not line:
                skipped["blank line"] += 1
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                skipped["non-JSON line"] += 1
                continue
            t = doc.get("transaction")
            if not isinstance(t, dict):
                skipped["no 'transaction' object"] += 1
                continue
            ts = t.get("time_stamp")
            if not ts:
                skipped["missing time_stamp"] += 1
                continue
            try:
                tg = iso_from_asctime(ts)
            except (ValueError, TypeError):
                skipped["unparseable time_stamp"] += 1
                continue

            req = t.get("request") or {}
            msgs = t.get("messages") or []   # may be absent or [] for clean transactions
            # pick first 941/942 attack rule; else first message; else none
            chosen = None
            for m in msgs:
                rid = (m.get("details") or {}).get("ruleId", "")
                if rid.startswith(("941", "942")):
                    chosen = m
                    break
            if chosen is None and msgs:
                chosen = msgs[0]
            rid = (chosen.get("details") or {}).get("ruleId", "") if chosen else ""
            rmsg = chosen.get("message", "") if chosen else ""

            uri = req.get("uri", "")
            if SEARCH_ENDPOINT in uri:
                search += 1
            rows.append({
                "TimeGenerated": tg,
                "ClientIP": t.get("client_ip", ""),
                "RequestMethod": req.get("method", ""),
                "RequestURI": uri,
                "RuleId": rid,
                "RuleMessage": rmsg,
                "AttackCategory": attack_cat(rid),
                "ParanoiaLevel": paranoia,
            })
    return rows, skipped, total, search


def parse_access(path: Path, paranoia: int):
    """Return (rows, skipped_counter, total_lines, search_count)."""
    rows, skipped = [], Counter()
    total = search = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total += 1
            raw = line.rstrip("\n")
            if not raw.strip():
                skipped["blank line"] += 1
                continue
            m = ACCESS_RE.match(raw)
            if not m:
                skipped["not NGINX combined format"] += 1
                continue
            ip, ts, method, uri, _proto, status, nbytes, _ref, ua = m.groups()
            try:
                tg = iso_from_nginx(ts)
            except (ValueError, TypeError):
                skipped["unparseable time field"] += 1
                continue
            if SEARCH_ENDPOINT in uri:
                search += 1
            rows.append({
                "TimeGenerated": tg,
                "ClientIP": ip,
                "RequestMethod": method,
                "RequestURI": uri,
                "StatusCode": int(status),
                "BytesSent": int(nbytes) if nbytes.isdigit() else 0,
                "UserAgent": ua,
                "ParanoiaLevel": paranoia,
            })
    return rows, skipped, total, search


def parse_file(path: Path, kind: str, paranoia: int):
    return (parse_audit if kind == "audit" else parse_access)(path, paranoia)


# ----------------------------------------------------------------------------
# Upload
# ----------------------------------------------------------------------------
def require_env():
    missing = [v for v in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
               if not os.environ.get(v)]
    if missing:
        sys.exit("ERROR: missing required environment variable(s): "
                 + ", ".join(missing) + "\nSet them before running a real upload. Aborting.")
    return (os.environ["AZURE_TENANT_ID"],
            os.environ["AZURE_CLIENT_ID"],
            os.environ["AZURE_CLIENT_SECRET"])


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def upload_rows_sdk(rows, stream, fname):
    """Preferred path: azure-identity + azure-monitor-ingestion."""
    from azure.identity import ClientSecretCredential
    from azure.monitor.ingestion import LogsIngestionClient
    from azure.core.exceptions import HttpResponseError

    tenant, client_id, secret = require_env()
    cred = ClientSecretCredential(tenant_id=tenant, client_id=client_id, client_secret=secret)
    client = LogsIngestionClient(endpoint=DCE_ENDPOINT, credential=cred, logging_enable=False)

    uploaded, failed = 0, 0
    failures = []

    def on_error(e):
        nonlocal failed
        n = len(e.failed_logs)
        failed += n
        failures.append(str(getattr(e, "error", e))[:500])

    for batch in chunked(rows, BATCH_SIZE):
        try:
            client.upload(rule_id=DCR_IMMUTABLE_ID, stream_name=stream,
                          logs=batch, on_error=on_error)
            uploaded += len(batch)  # on_error subtracts failures via its own count
        except HttpResponseError as ex:
            failed += len(batch)
            body = getattr(getattr(ex, "response", None), "text", lambda: "")()
            failures.append(f"HTTP {getattr(ex, 'status_code', '?')}: {str(ex)[:300]} {body[:300]}")
            print(f"    [{fname}] batch FAILED: HTTP {getattr(ex,'status_code','?')}: {str(ex)[:200]}")
    uploaded -= failed
    return uploaded, failed, failures


def main():
    ap = argparse.ArgumentParser(description="Upload WAF logs to Sentinel (Logs Ingestion API).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Parse and report only; send nothing to Azure.")
    args = ap.parse_args()

    mode = "DRY-RUN (no data will be sent)" if args.dry_run else "LIVE UPLOAD"
    print(f"=== Sentinel uploader - mode: {mode} ===")
    print(f"DCE: {DCE_ENDPOINT}")
    print(f"DCR: {DCR_IMMUTABLE_ID}\n")

    grand_parsed = grand_skipped = grand_uploaded = grand_failed = 0
    expected_audit_search = {"pl1_audit.log": 701, "pl2_audit.log": 702}

    for fname, kind, pl, stream in FILES:
        path = SI / fname
        if not path.exists():
            print(f"!! MISSING FILE: {path}  - skipping\n")
            continue
        rows, skipped, total, search = parse_file(path, kind, pl)
        n_skipped = sum(skipped.values())
        grand_parsed += len(rows)
        grand_skipped += n_skipped

        print(f"--- {fname}  [{kind}, PL{pl} -> {stream}] ---")
        print(f"    total lines     : {total}")
        print(f"    rows parsed     : {len(rows)}")
        print(f"    rows skipped    : {n_skipped}")
        for reason, cnt in skipped.most_common():
            print(f"        - {reason}: {cnt}")
        print(f"    {SEARCH_ENDPOINT} hits: {search}")
        if kind == "audit":
            exp = expected_audit_search.get(fname)
            if exp is not None and abs(search - exp) > 5:
                print(f"    *** WARNING: expected ~{exp} search hits, got {search} "
                      f"(diff {search - exp}). Investigate before live upload. ***")

        if args.dry_run:
            if rows:
                print("    sample row:")
                print("      " + json.dumps(rows[0], ensure_ascii=False))
        else:
            up, fl, failures = upload_rows_sdk(rows, stream, fname)
            grand_uploaded += up
            grand_failed += fl
            print(f"    rows UPLOADED   : {up}")
            print(f"    rows FAILED     : {fl}")
            for f in failures:
                print(f"        ! {f}")
        print()

    print("=== TOTALS ===")
    print(f"  parsed:   {grand_parsed}")
    print(f"  skipped:  {grand_skipped}")
    if not args.dry_run:
        print(f"  uploaded: {grand_uploaded}")
        print(f"  failed:   {grand_failed}")
    else:
        print("  (dry-run - nothing sent)")


if __name__ == "__main__":
    main()
